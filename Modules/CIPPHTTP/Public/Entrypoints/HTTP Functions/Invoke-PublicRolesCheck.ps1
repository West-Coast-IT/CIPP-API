using namespace System.Net
using namespace Microsoft.Azure.Functions.PowerShellWorker

function Invoke-PublicRolesCheck {
    [CmdletBinding()]
    param(
        $Request,
        $TriggerMetadata,

        [string[]]$Roles = @(
            'anonymous',
            'authenticated',
            'superadmin',
            'admin',
            'editor',
            'readonly'
        )
    )

    try {
        $allowedRoles = @(
            'superadmin',
            'admin',
            'editor',
            'readonly'
        )

        $roleClaimTypes = @(
            'roles',
            'role',
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
        )

        $claims = @($Request.Body.claims)

        $rolesToReturn = $claims |
            Where-Object { $_.typ -in $roleClaimTypes -and $_.val } |
            ForEach-Object { $_.val } |
            Where-Object { $_ -in $allowedRoles } |
            Sort-Object -Unique

        return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Headers    = @{ 'Content-Type' = 'application/json' }
            Body       = @{ roles = @($rolesToReturn) } | ConvertTo-Json -Depth 5 -Compress
        })
    } catch {
        return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Headers    = @{ 'Content-Type' = 'application/json' }
            Body       = @{ roles = @() } | ConvertTo-Json -Depth 5 -Compress
        })
    }
}