using Amazon.DynamoDBv2.DataModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthLambda
{
    [DynamoDBTable("Users")]
    public class User
    {
       // [DynamoDBHashKey("id")]
       // public int? Id { get; set; }
        [DynamoDBHashKey("email")]
        public string? Email { get; set; }
        [DynamoDBProperty("id")]
        public string? Id { get; set; }
        [DynamoDBProperty("password")]
        public string? Password { get; set; }
        [DynamoDBProperty("username")]
        public string? Username { get; set; }
        [DynamoDBProperty("role")]
        public string? Role { get; set; }

    }
}
