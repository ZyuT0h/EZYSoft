using System.Text.Json;

namespace EZYSoft.Helpers
{
    public class RecaptchaHelper
    {
        private const string RECAPTCHA_URL = "https://www.google.com/recaptcha/api/siteverify";

        // Method to validate the reCAPTCHA token
        public static async Task<bool> VerifyRecaptchaAsync(string secretKey, string token, string action)
        {
            using (var client = new HttpClient())
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("secret", secretKey),
                    new KeyValuePair<string, string>("response", token)
                });

                var response = await client.PostAsync(RECAPTCHA_URL, content);
                var jsonResponse = await response.Content.ReadAsStringAsync();

                // Log the full JSON response
                Console.WriteLine("Google reCAPTCHA API Response: " + jsonResponse);

                // Deserialize the JSON response into the RecaptchaResponse class
                var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

                // Check if the response is valid and the score meets the threshold
                return result?.success == true 
                    && result.score >= 0.5 // Adjust threshold as needed
                    && result.action == action;
            }
        }

        // Nested class to represent the reCAPTCHA API response
        private class RecaptchaResponse
        {
            public bool success { get; set; }
            public float score { get; set; }
            public string action { get; set; }
            public string challenge_ts { get; set; }
            public string hostname { get; set; }
        }
    }
}
