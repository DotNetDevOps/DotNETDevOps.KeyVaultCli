using McMaster.Extensions.CommandLineUtils;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DotNETDevOps.KeyVaultCli
{

    [Command(Name = "vault", Description = "vault crypto helper")]
    [HelpOption("-?")]
    class Program
    {
        private static X509Certificate2 buildSelfSignedServerCertificate(string CertificateName, string password)
        {
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);

            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={CertificateName}");

            using (RSA rsa = RSA.Create(2048 * 2))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));


                request.CertificateExtensions.Add(
                   new X509EnhancedKeyUsageExtension(
                       new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                request.CertificateExtensions.Add(sanBuilder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));
                bool isWindows = System.Runtime.InteropServices.RuntimeInformation
                              .IsOSPlatform(OSPlatform.Windows);
                if (isWindows)
                    certificate.FriendlyName = CertificateName;

                return certificate;
                // return new X509Certificate2(certificate.Export(X509ContentType.Pfx, password), password, X509KeyStorageFlags.MachineKeySet);
            }
        }

        static Task<int> Main(string[] args) => CommandLineApplication.ExecuteAsync<Program>(args);


        [Argument(0, Description = "The clientId to use to accesss keyvault")]
        private string ClientId { get; }

        [Required]
        [Option("-s|--secretName <SECRET_NAME>", "The secretName", CommandOptionType.SingleValue)]
        public string SecretName { get; set; }

        [Required]
        [Option("-v|--vaultName <VAULT_NAME>", "The vault name", CommandOptionType.SingleValue)]
        public string VaultName { get; set; }

        [Required]
        [Option("-c|--certificateName <CERTIFICATE_NAME>", "The certificate secret name", CommandOptionType.SingleValue)]
        public string CertificateName { get; set; }

        [Option("-i|--install", "Install the certificate to the machine",CommandOptionType.NoValue)]
        public bool Install { get; set; }

        [Option("-o|--out", "save the certificate", CommandOptionType.SingleValue)]
        public string Out { get; set; }

        private async Task<int> OnExecuteAsync(CommandLineApplication app)
        {

        
 


            var vaultUri = $"https://{VaultName}.vault.azure.net";

            var keyvaultClient = new KeyVaultClient(GetToken);
            var secret = await keyvaultClient.GetSecretAsync($"{vaultUri}/secrets/{SecretName}");


            var certs = await keyvaultClient.GetSecretVersionsAsync(vaultUri, CertificateName);
            X509Certificate2 cert = null;
             
            if (!certs.Any())
            {
                var x509Certificate = cert = buildSelfSignedServerCertificate(CertificateName, "");
                await keyvaultClient.SetSecretAsync(vaultUri, CertificateName, Convert.ToBase64String(x509Certificate.Export(X509ContentType.Pkcs12,"")), null, "application/x-pkcs12");

            }
            else
            {
                var certSecret = await keyvaultClient.GetSecretAsync(certs.First().Id);
                cert = new X509Certificate2(Convert.FromBase64String(certSecret.Value),"", X509KeyStorageFlags.Exportable);
            }


            byte[] encoded = Encoding.Unicode.GetBytes(secret.Value);
            var content = new ContentInfo(encoded);
            var env = new EnvelopedCms(content);
            env.Encrypt(new CmsRecipient(cert));

            string encrypted64 = Convert.ToBase64String(env.Encode());
            Console.WriteLine(encrypted64);

            if (!string.IsNullOrEmpty(Out))
            {
                File.WriteAllBytes(Out,cert.Export(X509ContentType.Pkcs12,""));
            }


            if (Install)
            {
                Console.WriteLine($"installing {cert.Thumbprint} to CurrentUser.My");



                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(cert);
                    store.Close();
                }
                try
                {
                    using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        store.Add(cert);
                        store.Close();
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to add to localmachine");
                }

            }
            return 0;



        }
        private static ConcurrentDictionary<string, AsyncExpiringLazy<string>> cache = new ConcurrentDictionary<string, AsyncExpiringLazy<string>>();

        private async Task<string> GetToken(string authority, string resource, string scope)
        {
            var token = cache.GetOrAdd(authority, new AsyncExpiringLazy<string>(async (old) =>
            {
                var ctx = new AuthenticationContext(authority);
            

            var tokenrequest = await ctx.AcquireDeviceCodeAsync(resource,ClientId);
                Console.WriteLine(tokenrequest.Message);

                var t = await ctx.AcquireTokenByDeviceCodeAsync(tokenrequest);
                return new ExpirationMetadata<string>
                {
                    ValidUntil = t.ExpiresOn,
                    Result = t.AccessToken
                };
            }));



            return await token.Value();
        }
    }

    internal struct ExpirationMetadata<T>
    {
        public T Result { get; set; }

        public DateTimeOffset ValidUntil { get; set; }
    }

    internal class AsyncExpiringLazy<T>
    {
        private readonly SemaphoreSlim _syncLock = new SemaphoreSlim(initialCount: 1);
        private readonly Func<ExpirationMetadata<T>, Task<ExpirationMetadata<T>>> _valueProvider;
        private ExpirationMetadata<T> _value;

        public AsyncExpiringLazy(Func<ExpirationMetadata<T>, Task<ExpirationMetadata<T>>> valueProvider)
        {
            if (valueProvider == null) throw new ArgumentNullException(nameof(valueProvider));
            _valueProvider = valueProvider;
        }

        private bool IsValueCreatedInternal => _value.Result != null && _value.ValidUntil > DateTimeOffset.UtcNow;

        public async Task<bool> IsValueCreated()
        {
            await _syncLock.WaitAsync().ConfigureAwait(false);
            try
            {
                return IsValueCreatedInternal;
            }
            finally
            {
                _syncLock.Release();
            }
        }

        public async Task<T> Value()
        {
            await _syncLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (IsValueCreatedInternal)
                {
                    return _value.Result;
                }

                var result = await _valueProvider(_value).ConfigureAwait(false);
                _value = result;
                return _value.Result;
            }
            finally
            {
                _syncLock.Release();
            }
        }

        public async Task Invalidate()
        {
            await _syncLock.WaitAsync().ConfigureAwait(false);
            _value = default(ExpirationMetadata<T>);
            _syncLock.Release();
        }
    }
}
