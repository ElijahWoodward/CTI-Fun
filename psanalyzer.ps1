# Ask for the OpenAI API key
$apiKey = Read-Host "Please enter your OpenAI API key"

# Optionally ask for an Organization ID
$organizationId = Read-Host "Enter your OpenAI Organization ID (Press Enter if none)"

# Base URL for OpenAI Chat API
$baseUri = "https://api.openai.com/v1/chat/completions"

# Set headers with the API Key and optionally the Organization ID
$headers = @{
    "Authorization" = "Bearer $apiKey"
    "Content-Type" = "application/json"
}

# Include the organization ID in the header if provided
if (-not [string]::IsNullOrWhiteSpace($organizationId)) {
    $headers["OpenAI-Organization"] = $organizationId
}

# Function to send website content to OpenAI and get responses
function Analyze-WebsiteContent($url) {
    # Get the content from the URL
    $webContent = Invoke-WebRequest -Uri $url

    # Prepare the body with the system message and the website content
    $body = @{
        model = "gpt-3.5-turbo"
        messages = @(
            @{
                role = "system"
                content = "You are a sophisticated AI trained in cybersecurity and malware analysis. Analyze the given code, identify potential exploits, and create SNORT rules for detecting these exploits."
            },
            @{
                role = "user"
                content = $webContent.Content
            }
        )
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $baseUri -Method Post -Headers $headers -Body $body

    return $response.choices[0].message.content
}

# Get URL from user and analyze its content
$url = Read-Host "Please enter a URL for analysis"
$analysisResult = Analyze-WebsiteContent $url
Write-Host "Analysis Result: $analysisResult"
