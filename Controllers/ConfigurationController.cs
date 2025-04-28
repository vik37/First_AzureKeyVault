using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using First_AzureKeyVault.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace First_AzureKeyVault.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class ConfigurationController : ControllerBase
	{
		private readonly IConfiguration _configuration;

		public ConfigurationController(IConfiguration configuration)
		{
			_configuration = configuration;
		}

		[HttpGet]
		public IActionResult GetConfiguration()
		{
			var keyVaultUrl = _configuration["KeyVaultConfiguration:KeyVaultURL"];
			var secretKey = _configuration["KeyVaultConfiguration:MySecretKey"];

			var manageIdentityCredential = new DefaultAzureCredential();

			var secretClient = new SecretClient(new Uri(keyVaultUrl), manageIdentityCredential);
			var secretValue = secretClient.GetSecret(secretKey).Value.Value;

			return Ok(secretValue);
		}

		[HttpGet("all")]
		public IActionResult GetAll()
		{
			var keyValueSecrets = new List<ValueSecrets>();
			try
			{
				var keyVaultUrl = _configuration["KeyVaultConfiguration:KeyVaultURL"];

				var clientId = _configuration["AzureAD:ClientId"];
				var clientSecret = _configuration["AzureAD:ClientSecret"];
				var tenantId = _configuration["AzureAD:TenantId"];

				var secretClient = new SecretClient(new Uri(keyVaultUrl), new ClientSecretCredential(tenantId, clientId, clientSecret));

				if (!string.IsNullOrEmpty(keyVaultUrl))
				{
					var rootConfiguration = (IConfigurationRoot)_configuration;

					var secrets = new Dictionary<string, string>();

					var secretProperties = secretClient.GetPropertiesOfSecrets();

					foreach (var secretProperty in secretProperties)
					{
						var secretName = secretProperty.Name;
						var secretValue = secretClient.GetSecret(secretName).Value.Value;

						keyValueSecrets.Add(new ValueSecrets { Name = secretName, Value = secretValue });
					}
				}
				else
				{
					return BadRequest("KEy Vault URL is Missing");
				}
			}
			catch (Exception ex)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, ex);
			}

			return Ok(keyValueSecrets);
		}

		[HttpPost]
		public IActionResult Add(ValueSecrets keyValueSecrets)
		{
			string secretId = string.Empty;
			try
			{
				var keyVaultUrl = _configuration["KeyVaultConfiguration:KeyVaultURL"];

				var clientId = _configuration["AzureAD:ClientId"];
				var clientSecret = _configuration["AzureAD:ClientSecret"];
				var tenantId = _configuration["AzureAD:TenantId"];

				var secretClient = new SecretClient(new Uri(keyVaultUrl), new ClientSecretCredential(tenantId, clientId, clientSecret));

				if (!string.IsNullOrEmpty(keyVaultUrl))
				{
					var rootConfiguration = (IConfigurationRoot)_configuration;

					var secrets = new Dictionary<string, string>();

					secretId = secretClient.SetSecret(keyValueSecrets.Name, keyValueSecrets.Value).Value.Id.ToString();
				}
				else
				{
					return BadRequest("KEy Vault URL is Missing");
				}
			}
			catch (Exception ex)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, ex);
			}

			return Ok($"Secret ID: {secretId}");
		}

		[HttpPut]
		public IActionResult Update([FromBody] ValueSecrets keyValueSecrets)
		{
			try
			{
				var keyVaultUrl = _configuration["KeyVaultConfiguration:KeyVaultURL"];

				var clientId = _configuration["AzureAD:ClientId"];
				var clientSecret = _configuration["AzureAD:ClientSecret"];
				var tenantId = _configuration["AzureAD:TenantId"];

				var secretClient = new SecretClient(new Uri(keyVaultUrl), new ClientSecretCredential(tenantId, clientId, clientSecret));

				if (!string.IsNullOrEmpty(keyVaultUrl))
				{
					var rootConfiguration = (IConfigurationRoot)_configuration;

					var secrets = new Dictionary<string, string>();

					var secretProperty = secretClient.GetPropertiesOfSecrets().FirstOrDefault(x => x.Name == keyValueSecrets.Name);

					if (secretProperty is null)
						return NotFound("Key Vault Secret Property does not exist");

					secretClient.SetSecret(secretProperty.Name, keyValueSecrets.Value);

					//secretClient.UpdateSecretProperties(secretProperty);
				}
				else
				{
					return BadRequest("KEy Vault URL is Missing");
				}
			}
			catch (Exception ex)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, ex);
			}

			return Ok(keyValueSecrets);
		}
	}
}
