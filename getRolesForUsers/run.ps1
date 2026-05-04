using namespace System.Net

param($Request, $TriggerMetadata)

try {
    # Define allowed roles used by CIPP
    $allowedRoles = @(
        "superadmin",
        "admin",
        "editor",
        "readonly"
    )

    # Support multiple possible Entra role claim types
    $roleClaimTypes = @(
        "roles",
        "role",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    )

    # Read request body from SWA
    $body = $Request.Body

    if (-not $body) {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Headers    = @{ "Content-Type" = "application/json" }
            Body       = @{ roles = @() } | ConvertTo-Json -Depth 5
        })
        return
    }

    # Extract claims
    $claims = @($body.claims)

    # Pull role values from claims
    $entraRoles = $claims |
        Where-Object { $_.typ -in $roleClaimTypes -and $_.val } |
        ForEach-Object { $_.val }

    # Filter only allowed roles and remove duplicates
    $rolesToReturn = $entraRoles |
        Where-Object { $_ -in $allowedRoles } |
        Sort-Object -Unique

    # Return roles in SWA format
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Headers    = @{ "Content-Type" = "application/json" }
        Body       = @{ roles = @($rolesToReturn) } | ConvertTo-Json -Depth 5
    })
}
catch {
    # Fail safe: return no roles rather than erroring
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Headers    = @{ "Content-Type" = "application/json" }
        Body       = @{ roles = @() } | ConvertTo-Json -Depth 5
    })
}
