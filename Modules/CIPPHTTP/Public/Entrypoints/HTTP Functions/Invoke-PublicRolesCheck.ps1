function Invoke-PublicRolesCheck {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Public
    #>
    [CmdletBinding()]
    param(
        $Request,
        $TriggerMetadata
    )

    $allowedRoles = @(
        'superadmin',
        'admin',
        'authenticated',
        'anonymous',
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

    $Body = @{
        roles = @($rolesToReturn)
    }

    return [HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = ($Body | ConvertTo-Json -Depth 5)
    }
}