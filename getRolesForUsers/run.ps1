using namespace System.Net

param($Request, $TriggerMetadata)

try {
    $allowedRoles = @(
        "superadmin",
        "admin",
        "editor",
        "readonly"
    )

    $body = $Request.Body

    if (-not $body) {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Headers    = @{ "Content-Type" = "application/json" }
            Body       = @{ roles = @() } | ConvertTo-Json -Depth 5
        })
        return
    }

    $claims = @($body.claims)

    $entraRoles = $claims |
        Where-Object { $_.typ -eq "roles" -and $_.val } |
        ForEach-Object { $_.val }

    $rolesToReturn = $entraRoles |
        Where-Object { $_ -in $allowedRoles } |
        Sort-Object -Unique

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Headers    = @{ "Content-Type" = "application/json" }
        Body       = @{ roles = @($rolesToReturn) } | ConvertTo-Json -Depth 5
    })
}
catch {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Headers    = @{ "Content-Type" = "application/json" }
        Body       = @{ roles = @() } | ConvertTo-Json -Depth 5
    })
}
