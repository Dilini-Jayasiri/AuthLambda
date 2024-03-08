using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2;
using Amazon.Lambda.Core;
using System.Security.Claims;
using System.Text;
using Amazon.Lambda.APIGatewayEvents;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Serilog;
using NLog.Fluent;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace AuthLambda;

public class Function
{
    private readonly AmazonDynamoDBClient _dynamoDbClient;
    private readonly DynamoDBContext _dbContext;


    public Function()
    {
        _dynamoDbClient = new AmazonDynamoDBClient();
        _dbContext = new DynamoDBContext(_dynamoDbClient);
    }
    public async Task<APIGatewayHttpApiV2ProxyResponse> CreateUserAsync(APIGatewayHttpApiV2ProxyRequest request, ILambdaContext context)
    {
        try
        {

            var userRequest = JsonConvert.DeserializeObject<User>(request.Body);
            var existingUser = await _dbContext.LoadAsync<User>(userRequest.Email);
            if (existingUser != null)
            {
                var errorMessage = $"User with email {userRequest.Email} already exists.";
                LambdaLogger.Log(errorMessage);

                return new APIGatewayHttpApiV2ProxyResponse
                {
                   // Body = errorMessage,
                   Body= "User with this email already exists",
                    StatusCode = 400,
                    Headers = new Dictionary<string, string>
                {
                    { "Access-Control-Allow-Origin", "*" }
                }
                };
            
        }
            userRequest.Role = "0";
            await _dbContext.SaveAsync(userRequest);
            var message = $"User with Id {userRequest?.Id} Created";
            LambdaLogger.Log(message);
            return new APIGatewayHttpApiV2ProxyResponse
            {
                Body = message,
                StatusCode = 200,
                Headers = new Dictionary<string, string>
            {
                { "Access-Control-Allow-Origin", "*" }
            }
            };
        }
        catch (Exception ex)
        {
            return new APIGatewayHttpApiV2ProxyResponse
            {
                Body = ex.Message,
                StatusCode = 400
            };
        }
    }


    private const string key = "S0M3RAN0MS3CR3T!1!MAG1C!1!";
    public async Task<string> GenerateTokenAsync(APIGatewayHttpApiV2ProxyRequest request, ILambdaContext context)
    {
        try
        {
            var tokenRequest = JsonConvert.DeserializeObject<User>(request.Body);
            AmazonDynamoDBClient client = new();
            DynamoDBContext dbContext = new(client);
            //check if user exists in ddb
            var user = await dbContext.LoadAsync<User>(tokenRequest?.Email);
            if (user == null) throw new Exception("User Not Found!");
            if (user.Password != tokenRequest.Password) throw new Exception("Invalid Credentials!");
            var token = GenerateJWT(user);
            return token;
        } catch(Exception ex)
        {
            return ex.Message;
        }
        
    }


    public string GenerateJWT(User user)
    {
        var claims = new List<Claim> { new(ClaimTypes.Email, user.Email), new(ClaimTypes.Name, user.Username), new(ClaimTypes.Role, user.Role)};
        byte[] secret = Encoding.UTF8.GetBytes(key.PadRight(32)); // Ensure key is at least 32 bytes (256 bits)
        var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(claims: claims, expires: DateTime.UtcNow.AddMinutes(5), signingCredentials: signingCredentials);
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }

    public APIGatewayCustomAuthorizerResponse ValidateTokenAsync(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
    {
        try
        {
            var authToken = request.Headers["authorization"];
            var claimsPrincipal = GetClaimsPrincipal(authToken);
            var effect = claimsPrincipal == null ? "Deny" : "Allow";
            var principalId = claimsPrincipal == null ? "401" : claimsPrincipal?.FindFirst(ClaimTypes.Name)?.Value;
            return new APIGatewayCustomAuthorizerResponse()
            {
                PrincipalID = principalId,
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                {
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>
            {
                new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                {
                    Effect = effect,
                    Resource = new HashSet<string> { "arn:aws:execute-api:us-east-1:540131121268:w9nbvf6p6e/*/*" },
                    Action = new HashSet<string> { "execute-api:Invoke" }
                }
            }
                }
            };
        } catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return null;
        }
        
    }
    private ClaimsPrincipal GetClaimsPrincipal(string authToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParams = new TokenValidationParameters()
        {
            ValidateLifetime = true,
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key.PadRight(32))),
        };
        try
        {
            return tokenHandler.ValidateToken(authToken, validationParams, out SecurityToken securityToken);
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Error occurred during token validation");
            return null;
        }
    }
}
