#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Jenkins", "GitLab", "Travis", "CircleCI", "All")]
    [string]$Platform = "All",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Build", "Test", "Deploy", "Full")]
    [string]$Operation = "Full",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$PSScriptRoot\logs\cicd_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not (Get-Module -Name PowerShellGet -ListAvailable)) {
    Install-Module -Name PowerShellGet -Force -Scope CurrentUser
}

$RequiredModules = @(
    @{ Name = "PowerShellForGitHub"; MinimumVersion = "0.16.0" },
    @{ Name = "Pester"; MinimumVersion = "5.0.0" },
    @{ Name = "PSScriptAnalyzer"; MinimumVersion = "1.20.0" }
)

foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -Name $Module.Name -ListAvailable | Where-Object { $_.Version -ge $Module.MinimumVersion })) {
        Install-Module -Name $Module.Name -MinimumVersion $Module.MinimumVersion -Force -Scope CurrentUser
    }
    Import-Module -Name $Module.Name -Force
}

class CICDConfig {
    [string]$Platform
    [string]$BaseUrl
    [string]$Token
    [string]$Username
    [string]$ProjectId
    [hashtable]$Headers
    [string]$Repository
    [string]$Branch
    
    CICDConfig([string]$platform, [hashtable]$config) {
        $this.Platform = $platform
        $this.BaseUrl = $config.BaseUrl
        $this.Token = $config.Token
        $this.Username = $config.Username
        $this.ProjectId = $config.ProjectId
        $this.Repository = $config.Repository
        $this.Branch = $config.Branch -or "main"
        $this.Headers = @{}
    }
}

class BuildResult {
    [string]$Platform
    [string]$Status
    [string]$BuildId
    [string]$Message
    [datetime]$Timestamp
    [hashtable]$Artifacts
    
    BuildResult([string]$platform, [string]$status, [string]$buildId, [string]$message) {
        $this.Platform = $platform
        $this.Status = $status
        $this.BuildId = $buildId
        $this.Message = $message
        $this.Timestamp = Get-Date
        $this.Artifacts = @{}
    }
}

function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $colors = @{
        "Info" = "White"
        "Warning" = "Yellow"
        "Error" = "Red"
        "Success" = "Green"
    }
    
    Write-Host $logEntry -ForegroundColor $colors[$Level]
    
    if ($LogPath) {
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $logEntry
    }
}

function Get-SecureCredentials {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Platform,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    try {
        $credPath = "$env:USERPROFILE\.cicd\credentials_$Platform.xml"
        
        if ($Config.Token) {
            $secureToken = ConvertTo-SecureString -String $Config.Token -AsPlainText -Force
        } elseif (Test-Path $credPath) {
            $credential = Import-Clixml -Path $credPath
            $secureToken = $credential.Password
        } else {
            $credential = Get-Credential -Message "Enter credentials for $Platform"
            $credDir = Split-Path $credPath -Parent
            if (-not (Test-Path $credDir)) {
                New-Item -ItemType Directory -Path $credDir -Force | Out-Null
            }
            $credential | Export-Clixml -Path $credPath
            $secureToken = $credential.Password
        }
        
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve credentials for $Platform`: $_" -Level "Error"
        throw
    }
}

function Initialize-CICDConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    
    try {
        if (-not (Test-Path $ConfigPath)) {
            Write-LogMessage -Message "Config file not found at $ConfigPath" -Level "Error"
            throw "Configuration file not found"
        }
        
        $configData = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        $configs = @{}
        
        foreach ($platform in @("Jenkins", "GitLab", "Travis", "CircleCI")) {
            if ($configData.$platform) {
                $platformConfig = [hashtable]($configData.$platform | ConvertTo-Json | ConvertFrom-Json -AsHashtable)
                $configs[$platform] = [CICDConfig]::new($platform, $platformConfig)
                
                $token = Get-SecureCredentials -Platform $platform -Config $platformConfig
                $configs[$platform].Token = $token
                
                switch ($platform) {
                    "Jenkins" {
                        $configs[$platform].Headers = @{
                            "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($configs[$platform].Username):$token"))
                            "Content-Type" = "application/json"
                        }
                    }
                    "GitLab" {
                        $configs[$platform].Headers = @{
                            "PRIVATE-TOKEN" = $token
                            "Content-Type" = "application/json"
                        }
                    }
                    "Travis" {
                        $configs[$platform].Headers = @{
                            "Authorization" = "token $token"
                            "Travis-API-Version" = "3"
                            "Content-Type" = "application/json"
                        }
                    }
                    "CircleCI" {
                        $configs[$platform].Headers = @{
                            "Circle-Token" = $token
                            "Content-Type" = "application/json"
                        }
                    }
                }
            }
        }
        
        return $configs
    }
    catch {
        Write-LogMessage -Message "Failed to initialize configuration: $_" -Level "Error"
        throw
    }
}

function Invoke-RestApiCall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",
        [Parameter(Mandatory = $false)]
        [object]$Body = $null,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )
    
    $retryCount = 0
    $lastError = $null
    
    while ($retryCount -lt $MaxRetries) {
        try {
            $params = @{
                Uri = $Uri
                Headers = $Headers
                Method = $Method
                TimeoutSec = $TimeoutSeconds
                UseBasicParsing = $true
            }
            
            if ($Body) {
                if ($Body -is [string]) {
                    $params.Body = $Body
                } else {
                    $params.Body = $Body | ConvertTo-Json -Depth 10
                }
            }
            
            $response = Invoke-RestMethod @params
            return $response
        }
        catch {
            $lastError = $_
            $retryCount++
            
            if ($retryCount -lt $MaxRetries) {
                $waitTime = [math]::Pow(2, $retryCount) * 5
                Write-LogMessage -Message "API call failed, retrying in $waitTime seconds... (Attempt $retryCount/$MaxRetries)" -Level "Warning"
                Start-Sleep -Seconds $waitTime
            }
        }
    }
    
    Write-LogMessage -Message "API call failed after $MaxRetries attempts: $($lastError.Exception.Message)" -Level "Error"
    throw $lastError
}

function Start-JenkinsBuild {
    param(
        [Parameter(Mandatory = $true)]
        [CICDConfig]$Config,
        [Parameter(Mandatory = $true)]
        [string]$JobName,
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )
    
    try {
        Write-LogMessage -Message "Starting Jenkins build for job: $JobName" -Level "Info"
        
        $buildUri = if ($Parameters.Count -gt 0) {
            "$($Config.BaseUrl)/job/$JobName/buildWithParameters"
        } else {
            "$($Config.BaseUrl)/job/$JobName/build"
        }
        
        $response = Invoke-RestApiCall -Uri $buildUri -Headers $Config.Headers -Method "POST" -Body $Parameters
        
        Start-Sleep -Seconds 2
        
        $queueUri = "$($Config.BaseUrl)/job/$JobName/lastBuild/api/json"
        $buildInfo = Invoke-RestApiCall -Uri $queueUri -Headers $Config.Headers
        
        return [BuildResult]::new("Jenkins", "Started", $buildInfo.number, "Build queued successfully")
    }
    catch {
        Write-LogMessage -Message "Jenkins build failed: $_" -Level "Error"
        return [BuildResult]::new("Jenkins", "Failed", "", $_.Exception.Message)
    }
}

function Start-GitLabPipeline {
    param(
        [Parameter(Mandatory = $true)]
        [CICDConfig]$Config,
        [Parameter(Mandatory = $false)]
        [string]$Ref = "main",
        [Parameter(Mandatory = $false)]
        [hashtable]$Variables = @{}
    )
    
    try {
        Write-LogMessage -Message "Starting GitLab pipeline for project: $($Config.ProjectId)" -Level "Info"
        
        $pipelineUri = "$($Config.BaseUrl)/api/v4/projects/$($Config.ProjectId)/pipeline"
        $body = @{
            ref = $Ref
            variables = @()
        }
        
        foreach ($key in $Variables.Keys) {
            $body.variables += @{
                key = $key
                value = $Variables[$key]
            }
        }
        
        $response = Invoke-RestApiCall -Uri $pipelineUri -Headers $Config.Headers -Method "POST" -Body $body
        
        return [BuildResult]::new("GitLab", "Started", $response.id, "Pipeline created successfully")
    }
    catch {
        Write-LogMessage -Message "GitLab pipeline failed: $_" -Level "Error"
        return [BuildResult]::new("GitLab", "Failed", "", $_.Exception.Message)
    }
}

function Start-TravisCI {
    param(
        [Parameter(Mandatory = $true)]
        [CICDConfig]$Config,
        [Parameter(Mandatory = $false)]
        [string]$Branch = "main"
    )
    
    try {
        Write-LogMessage -Message "Starting Travis CI build for repository: $($Config.Repository)" -Level "Info"
        
        $repoSlug = $Config.Repository -replace '/', '%2F'
        $buildUri = "$($Config.BaseUrl)/repo/$repoSlug/requests"
        
        $body = @{
            request = @{
                branch = $Branch
                message = "Triggered via PowerShell CI/CD script"
            }
        }
        
        $response = Invoke-RestApiCall -Uri $buildUri -Headers $Config.Headers -Method "POST" -Body $body
        
        return [BuildResult]::new("Travis", "Started", $response.request.id, "Build request submitted successfully")
    }
    catch {
        Write-LogMessage -Message "Travis CI build failed: $_" -Level "Error"
        return [BuildResult]::new("Travis", "Failed", "", $_.Exception.Message)
    }
}

function Start-CircleCIPipeline {
    param(
        [Parameter(Mandatory = $true)]
        [CICDConfig]$Config,
        [Parameter(Mandatory = $false)]
        [string]$Branch = "main",
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )
    
    try {
        Write-LogMessage -Message "Starting CircleCI pipeline for project: $($Config.Repository)" -Level "Info"
        
        $pipelineUri = "$($Config.BaseUrl)/v2/project/github/$($Config.Repository)/pipeline"
        
        $body = @{
            branch = $Branch
            parameters = $Parameters
        }
        
        $response = Invoke-RestApiCall -Uri $pipelineUri -Headers $Config.Headers -Method "POST" -Body $body
        
        return [BuildResult]::new("CircleCI", "Started", $response.id, "Pipeline triggered successfully")
    }
    catch {
        Write-LogMessage -Message "CircleCI pipeline failed: $_" -Level "Error"
        return [BuildResult]::new("CircleCI", "Failed", "", $_.Exception.Message)
    }
}

function Wait-ForBuildCompletion {
    param(
        [Parameter(Mandatory = $true)]
        [CICDConfig]$Config,
        [Parameter(Mandatory = $true)]
        [string]$BuildId,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 30,
        [Parameter(Mandatory = $false)]
        [int]$PollingIntervalSeconds = 30
    )
    
    $startTime = Get-Date
    $timeoutTime = $startTime.AddMinutes($TimeoutMinutes)
    
    while ((Get-Date) -lt $timeoutTime) {
        try {
            $status = Get-BuildStatus -Config $Config -BuildId $BuildId
            
            if ($status.Status -in @("Success", "Failed", "Cancelled")) {
                return $status
            }
            
            Write-LogMessage -Message "Build $BuildId status: $($status.Status). Waiting..." -Level "Info"
            Start-Sleep -Seconds $PollingIntervalSeconds
        }
        catch {
            Write-LogMessage -Message "Error checking build status: $_" -Level "Warning"
            Start-Sleep -Seconds $PollingIntervalSeconds
        }
    }
    
    Write-LogMessage -Message "Build $BuildId timed out after $TimeoutMinutes minutes" -Level "Error"
    return [BuildResult]::new($Config.Platform, "Timeout", $BuildId, "Build timed out")
}

function Get-BuildStatus {
    param(
        [Parameter(Mandatory = $true)]
        [CICDConfig]$Config,
        [Parameter(Mandatory = $true)]
        [string]$BuildId
    )
    
    try {
        switch ($Config.Platform) {
            "Jenkins" {
                $statusUri = "$($Config.BaseUrl)/job/$($Config.ProjectId)/$BuildId/api/json"
                $response = Invoke-RestApiCall -Uri $statusUri -Headers $Config.Headers
                
                $status = switch ($response.result) {
                    "SUCCESS" { "Success" }
                    "FAILURE" { "Failed" }
                    "ABORTED" { "Cancelled" }
                    default { "Running" }
                }
                
                return [BuildResult]::new("Jenkins", $status, $BuildId, $response.displayName)
            }
            
            "GitLab" {
                $statusUri = "$($Config.BaseUrl)/api/v4/projects/$($Config.ProjectId)/pipelines/$BuildId"
                $response = Invoke-RestApiCall -Uri $statusUri -Headers $Config.Headers
                
                $status = switch ($response.status) {
                    "success" { "Success" }
                    "failed" { "Failed" }
                    "cancelled" { "Cancelled" }
                    default { "Running" }
                }
                
                return [BuildResult]::new("GitLab", $status, $BuildId, $response.ref)
            }
            
            "Travis" {
                $statusUri = "$($Config.BaseUrl)/build/$BuildId"
                $response = Invoke-RestApiCall -Uri $statusUri -Headers $Config.Headers
                
                $status = switch ($response.state) {
                    "passed" { "Success" }
                    "failed" { "Failed" }
                    "cancelled" { "Cancelled" }
                    default { "Running" }
                }
                
                return [BuildResult]::new("Travis", $status, $BuildId, $response.branch.name)
            }
            
            "CircleCI" {
                $statusUri = "$($Config.BaseUrl)/v2/pipeline/$BuildId"
                $response = Invoke-RestApiCall -Uri $statusUri -Headers $Config.Headers
                
                $status = switch ($response.state) {
                    "success" { "Success" }
                    "failed" { "Failed" }
                    "cancelled" { "Cancelled" }
                    default { "Running" }
                }
                
                return [BuildResult]::new("CircleCI", $status, $BuildId, $response.trigger.type)
            }
        }
    }
    catch {
        Write-LogMessage -Message "Failed to get build status: $_" -Level "Error"
        return [BuildResult]::new($Config.Platform, "Unknown", $BuildId, $_.Exception.Message)
    }
}

function Invoke-LocalTests {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TestPath = ".\tests",
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\test-results.xml"
    )
    
    try {
        Write-LogMessage -Message "Running local tests..." -Level "Info"
        
        if (-not (Test-Path $TestPath)) {
            Write-LogMessage -Message "Test path not found: $TestPath" -Level "Warning"
            return @{ Status = "Skipped"; Message = "No tests found" }
        }
        
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Path = $TestPath
        $pesterConfig.Output.Verbosity = "Normal"
        $pesterConfig.TestResult.Enabled = $true
        $pesterConfig.TestResult.OutputPath = $OutputPath
        
        $results = Invoke-Pester -Configuration $pesterConfig
        
        $status = if ($results.FailedCount -eq 0) { "Success" } else { "Failed" }
        $message = "Tests: $($results.PassedCount) passed, $($results.FailedCount) failed, $($results.SkippedCount) skipped"
        
        Write-LogMessage -Message $message -Level $(if ($status -eq "Success") { "Success" } else { "Error" })
        
        return @{
            Status = $status
            Message = $message
            Results = $results
        }
    }
    catch {
        Write-LogMessage -Message "Test execution failed: $_" -Level "Error"
        return @{
            Status = "Failed"
            Message = $_.Exception.Message
            Results = $null
        }
    }
}

function Invoke-CodeAnalysis {
    param(
        [Parameter(Mandatory = $false)]
        [string]$SourcePath = ".\src",
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\analysis-results.xml"
    )
    
    try {
        Write-LogMessage -Message "Running code analysis..." -Level "Info"
        
        if (-not (Test-Path $SourcePath)) {
            Write-LogMessage -Message "Source path not found: $SourcePath" -Level "Warning"
            return @{ Status = "Skipped"; Message = "No source code found" }
        }
        
        $analysisResults = Invoke-ScriptAnalyzer -Path $SourcePath -Recurse -ReportSummary
        
        $criticalCount = ($analysisResults | Where-Object { $_.Severity -eq "Error" }).Count
        $warningCount = ($analysisResults | Where-Object { $_.Severity -eq "Warning" }).Count
        
        $status = if ($criticalCount -eq 0) { "Success" } else { "Failed" }
        $message = "Analysis: $criticalCount errors, $warningCount warnings"
        
        $analysisResults | Export-Clixml -Path $OutputPath
        
        Write-LogMessage -Message $message -Level $(if ($status -eq "Success") { "Success" } else { "Warning" })
        
        return @{
            Status = $status
            Message = $message
            Results = $analysisResults
        }
    }
    catch {
        Write-LogMessage -Message "Code analysis failed: $_" -Level "Error"
        return @{
            Status = "Failed"
            Message = $_.Exception.Message
            Results = $null
        }
    }
}

function Invoke-DeploymentProcess {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configs,
        [Parameter(Mandatory = $true)]
        [string]$Environment,
        [Parameter(Mandatory = $false)]
        [hashtable]$DeploymentParameters = @{}
    )
    
    try {
        Write-LogMessage -Message "Starting deployment to $Environment environment..." -Level "Info"
        
        $deploymentResults = @()
        
        foreach ($platformName in $Configs.Keys) {
            $config = $Configs[$platformName]
            
            try {
                $deploymentParams = @{
                    environment = $Environment
                    timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
                
                $deploymentParams += $DeploymentParameters
                
                switch ($platformName) {
                    "Jenkins" {
                        $result = Start-JenkinsBuild -Config $config -JobName "deploy-$Environment" -Parameters $deploymentParams
                    }
                    "GitLab" {
                        $result = Start-GitLabPipeline -Config $config -Ref $config.Branch -Variables $deploymentParams
                    }
                    "Travis" {
                        $result = Start-TravisCI -Config $config -Branch $config.Branch
                    }
                    "CircleCI" {
                        $result = Start-CircleCIPipeline -Config $config -Branch $config.Branch -Parameters $deploymentParams
                    }
                }
                
                $deploymentResults += $result
                Write-LogMessage -Message "Deployment initiated on $platformName`: $($result.Status)" -Level "Info"
            }
            catch {
                Write-LogMessage -Message "Deployment failed on $platformName`: $_" -Level "Error"
                $deploymentResults += [BuildResult]::new($platformName, "Failed", "", $_.Exception.Message)
            }
        }
        
        return $deploymentResults
    }
    catch {
        Write-LogMessage -Message "Deployment process failed: $_" -Level "Error"
        throw
    }
}

function New-BuildReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$BuildResults,
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\build-report.html"
    )
    
    try {
        $reportData = @{
            Timestamp = Get-Date
            Results = $BuildResults
            Summary = @{
                Total = $BuildResults.Count
                Success = ($BuildResults | Where-Object { $_.Status -eq "Success" }).Count
                Failed = ($BuildResults | Where-Object { $_.Status -eq "Failed" }).Count
                Running = ($BuildResults | Where-Object { $_.Status -eq "Running" }).Count
            }
        }
        
        $htmlReport = @'
<!DOCTYPE html>
<html>
<head>
    <title>CI/CD Build Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .result { margin: 10px 0; padding: 10px; border-radius: 5px; }
        .success { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .failed { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .running { background-color: #fff3cd; border: 1px solid #ffeaa7; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CI/CD Build Report</h1>
        <p>Generated: {0}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Builds: {1}</p>
        <p>Successful: {2}</p>
        <p>Failed: {3}</p>
        <p>Running: {4}</p>
    </div>
    
    <div class="results">
        <h2>Build Results</h2>
        <table>
            <tr>
                <th>Platform</th>
                <th>Status</th>
                <th>Build ID</th>
                <th>Message</th>
                <th>Timestamp</th>
            </tr>
'@ -f $reportData.Timestamp, $reportData.Summary.Total, $reportData.Summary.Success, $reportData.Summary.Failed, $reportData.Summary.Running
        
        foreach ($result in $BuildResults) {
            $cssClass = switch ($result.Status) {
                "Success" { "success" }
                "Failed" { "failed" }
                default { "running" }
            }
            
            $htmlReport += "            <tr class=`"$cssClass`">
                <td>$($result.Platform)</td>
                <td>$($result.Status)</td>
                <td>$($result.BuildId)</td>
                <td>$($result.Message)</td>
                <td>$($result.Timestamp)</td>
            </tr>"
        }
        
        $htmlReport += @'
        </table>
    </div>
</body>
</html>
'@
        
        $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-LogMessage -Message "Build report generated: $OutputPath" -Level "Success"
        
        return $OutputPath
    }
    catch {
        Write-LogMessage -Message "Failed to generate build report: $_" -Level "Error"
        throw
    }
}

function Invoke-CICDPipeline {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Platform,
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        [Parameter(Mandatory = $true)]
        [hashtable]$Configs
    )
    
    $results = @()
    
    try {
        $platformsToProcess = if ($Platform -eq "All") { $Configs.Keys } else { @($Platform) }
        
        foreach ($platformName in $platformsToProcess) {
            if (-not $Configs.ContainsKey($platformName)) {
                Write-LogMessage -Message "Configuration not found for platform: $platformName" -Level "Warning"
                continue
            }
            
            $config = $Configs[$platformName]
            
            switch ($Operation) {
                "Build" {
                    $result = switch ($platformName) {
                        "Jenkins" { Start-JenkinsBuild -Config $config -JobName "build-main" }
                        "GitLab" { Start-GitLabPipeline -Config $config -Ref $config.Branch }
                        "Travis" { Start-TravisCI -Config $config -Branch $config.Branch }
                        "CircleCI" { Start-CircleCIPipeline -Config $config -Branch $config.Branch }
                    }
                }
                
                "Test" {
                    $localTestResult = Invoke-LocalTests
                    $analysisResult = Invoke-CodeAnalysis
                    
                    if ($localTestResult.Status -eq "Success" -and $analysisResult.Status -eq "Success") {
                        $result = [BuildResult]::new($platformName, "Success", "local", "Local tests and analysis passed")
                    } else {
                        $result = [BuildResult]::new($platformName, "Failed", "local", "Local tests or analysis failed")
                    }
                }
                
                "Deploy" {
                    $deployResults = Invoke-DeploymentProcess -Configs @{$platformName = $config} -Environment "production"
                    $result = $deployResults[0]
                }
                
                "Full" {
                    $localTestResult = Invoke-LocalTests
                    $analysisResult = Invoke-CodeAnalysis
                    
                    if ($localTestResult.Status -eq "Success" -and $analysisResult.Status -eq "Success") {
                        $result = switch ($platformName) {
                            "Jenkins" { Start-JenkinsBuild -Config $config -JobName "full-pipeline" }
                            "GitLab" { Start-GitLabPipeline -Config $config -Ref $config.Branch }
                            "Travis" { Start-TravisCI -Config $config -Branch $config.Branch }
                            "CircleCI" { Start-CircleCIPipeline -Config $config -Branch $config.Branch }
                        }
                    } else {
                        $result = [BuildResult]::new($platformName, "Failed", "", "Pre-build validation failed")
                    }
                }
            }
            
            $results += $result
            Write-LogMessage -Message "Operation '$Operation' completed for $platformName`: $($result.Status)" -Level "Info"
        }
        
        return $results
    }
    catch {
        Write-LogMessage -Message "Pipeline execution failed: $_" -Level "Error"
        throw
    }
}

function Invoke-ParallelBuilds {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configs,
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )
    
    try {
        Write-LogMessage -Message "Starting parallel builds for operation: $Operation" -Level "Info"
        
        $jobs = @()
        
        foreach ($platformName in $Configs.Keys) {
            $config = $Configs[$platformName]
            
            $scriptBlock = {
                param($PlatformName, $Config, $Operation)
                
                try {
                    switch ($Operation) {
                        "Build" {
                            $result = switch ($PlatformName) {
                                "Jenkins" { Start-JenkinsBuild -Config $Config -JobName "build-main" }
                                "GitLab" { Start-GitLabPipeline -Config $Config -Ref $Config.Branch }
                                "Travis" { Start-TravisCI -Config $Config -Branch $Config.Branch }
                                "CircleCI" { Start-CircleCIPipeline -Config $Config -Branch $Config.Branch }
                            }
                        }
                        
                        "Deploy" {
                            $deployResults = Invoke-DeploymentProcess -Configs @{$PlatformName = $Config} -Environment "production"
                            $result = $deployResults[0]
                        }
                        
                        default {
                            $result = [BuildResult]::new($PlatformName, "Skipped", "", "Operation not supported in parallel mode")
                        }
                    }
                    
                    return $result
                }
                catch {
                    return [BuildResult]::new($PlatformName, "Failed", "", $_.Exception.Message)
                }
            }
            
            $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $platformName, $config, $Operation
            $jobs += @{ Job = $job; Platform = $platformName }
        }
        
        $results = @()
        $timeout = 300
        
        foreach ($jobInfo in $jobs) {
            try {
                $result = Receive-Job -Job $jobInfo.Job -Wait -Timeout $timeout
                if ($result) {
                    $results += $result
                } else {
                    $results += [BuildResult]::new($jobInfo.Platform, "Timeout", "", "Job timed out")
                }
            }
            catch {
                $results += [BuildResult]::new($jobInfo.Platform, "Failed", "", $_.Exception.Message)
            }
            finally {
                Remove-Job -Job $jobInfo.Job -Force
            }
        }
        
        return $results
    }
    catch {
        Write-LogMessage -Message "Parallel build execution failed: $_" -Level "Error"
        throw
    }
}

function Send-NotificationAlert {
    param(
        [Parameter(Mandatory = $true)]
        [array]$BuildResults,
        [Parameter(Mandatory = $false)]
        [string]$WebhookUrl = "",
        [Parameter(Mandatory = $false)]
        [string]$EmailRecipient = ""
    )
    
    try {
        $failedBuilds = $BuildResults | Where-Object { $_.Status -eq "Failed" }
        $successfulBuilds = $BuildResults | Where-Object { $_.Status -eq "Success" }
        
        $message = @"
CI/CD Pipeline Execution Complete

Summary:
- Total Builds: $($BuildResults.Count)
- Successful: $($successfulBuilds.Count)
- Failed: $($failedBuilds.Count)

$(if ($failedBuilds.Count -gt 0) {
    "Failed Builds:`n" + ($failedBuilds | ForEach-Object { "- $($_.Platform): $($_.Message)" } | Out-String)
})

Timestamp: $(Get-Date)
"@
        
        if ($WebhookUrl) {
            $webhookBody = @{
                text = $message
                username = "CI/CD Bot"
                icon_emoji = if ($failedBuilds.Count -eq 0) { ":white_check_mark:" } else { ":x:" }
            }
            
            try {
                Invoke-RestMethod -Uri $WebhookUrl -Method POST -Body ($webhookBody | ConvertTo-Json) -ContentType "application/json"
                Write-LogMessage -Message "Webhook notification sent successfully" -Level "Success"
            }
            catch {
                Write-LogMessage -Message "Failed to send webhook notification: $_" -Level "Warning"
            }
        }
        
        if ($EmailRecipient) {
            try {
                $emailParams = @{
                    To = $EmailRecipient
                    Subject = "CI/CD Pipeline Results - $(if ($failedBuilds.Count -eq 0) { 'SUCCESS' } else { 'FAILURE' })"
                    Body = $message
                    SmtpServer = "smtp.company.com"
                    From = "cicd-bot@company.com"
                }
                
                Send-MailMessage @emailParams
                Write-LogMessage -Message "Email notification sent successfully" -Level "Success"
            }
            catch {
                Write-LogMessage -Message "Failed to send email notification: $_" -Level "Warning"
            }
        }
    }
    catch {
        Write-LogMessage -Message "Notification sending failed: $_" -Level "Error"
    }
}

function Export-BuildArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [array]$BuildResults,
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = ".\artifacts"
    )
    
    try {
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        foreach ($result in $BuildResults) {
            if ($result.Status -eq "Success" -and $result.Artifacts.Count -gt 0) {
                $platformDir = Join-Path $OutputDirectory $result.Platform
                if (-not (Test-Path $platformDir)) {
                    New-Item -ItemType Directory -Path $platformDir -Force | Out-Null
                }
                
                foreach ($artifactName in $result.Artifacts.Keys) {
                    $artifactPath = Join-Path $platformDir "$($artifactName)_$($timestamp)"
                    $result.Artifacts[$artifactName] | Out-File -FilePath $artifactPath -Encoding UTF8
                }
            }
        }
        
        $manifestPath = Join-Path $OutputDirectory "manifest_$timestamp.json"
        $manifest = @{
            timestamp = Get-Date
            results = $BuildResults
            summary = @{
                total = $BuildResults.Count
                successful = ($BuildResults | Where-Object { $_.Status -eq "Success" }).Count
                failed = ($BuildResults | Where-Object { $_.Status -eq "Failed" }).Count
            }
        }
        
        $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestPath -Encoding UTF8
        
        Write-LogMessage -Message "Build artifacts exported to: $OutputDirectory" -Level "Success"
        return $OutputDirectory
    }
    catch {
        Write-LogMessage -Message "Failed to export build artifacts: $_" -Level "Error"
        throw
    }
}

function Clear-BuildCache {
    param(
        [Parameter(Mandatory = $false)]
        [string]$CacheDirectory = "$env:TEMP\cicd_cache"
    )
    
    try {
        if (Test-Path $CacheDirectory) {
            Remove-Item -Path $CacheDirectory -Recurse -Force
            Write-LogMessage -Message "Build cache cleared: $CacheDirectory" -Level "Info"
        }
        
        $credentialPaths = @(
            "$env:USERPROFILE\.cicd\credentials_*.xml",
            "$env:TEMP\cicd_*"
        )
        
        foreach ($pattern in $credentialPaths) {
            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
            if ($files) {
                $files | Remove-Item -Force
                Write-LogMessage -Message "Cleaned up temporary files: $($files.Count) files" -Level "Info"
            }
        }
    }
    catch {
        Write-LogMessage -Message "Cache cleanup failed: $_" -Level "Warning"
    }
}

function Test-Prerequisites {
    try {
        Write-LogMessage -Message "Checking prerequisites..." -Level "Info"
        
        $requirements = @(
            @{ Name = "PowerShell Version"; Check = { $PSVersionTable.PSVersion.Major -ge 5 } },
            @{ Name = "Internet Connectivity"; Check = { Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet } },
            @{ Name = "TLS 1.2 Support"; Check = { [Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12 } }
        )
        
        $allPassed = $true
        
        foreach ($req in $requirements) {
            try {
                $result = & $req.Check
                if ($result) {
                    Write-LogMessage -Message "$($req.Name): PASSED" -Level "Success"
                } else {
                    Write-LogMessage -Message "$($req.Name): FAILED" -Level "Error"
                    $allPassed = $false
                }
            }
            catch {
                Write-LogMessage -Message "$($req.Name): FAILED - $_" -Level "Error"
                $allPassed = $false
            }
        }
        
        return $allPassed
    }
    catch {
        Write-LogMessage -Message "Prerequisites check failed: $_" -Level "Error"
        return $false
    }
}

try {
    Write-LogMessage -Message "Starting CI/CD DevOps Integration Script" -Level "Info"
    Write-LogMessage -Message "Platform: $Platform, Operation: $Operation" -Level "Info"
    
    if (-not (Test-Prerequisites)) {
        Write-LogMessage -Message "Prerequisites check failed. Exiting." -Level "Error"
        exit 1
    }
    
    $configs = Initialize-CICDConfig -ConfigPath $ConfigPath
    
    if ($configs.Count -eq 0) {
        Write-LogMessage -Message "No valid configurations found. Exiting." -Level "Error"
        exit 1
    }
    
    Write-LogMessage -Message "Loaded configurations for: $($configs.Keys -join ', ')" -Level "Info"
    
    $results = Invoke-CICDPipeline -Platform $Platform -Operation $Operation -Configs $configs
    
    if ($results.Count -gt 0) {
        $reportPath = New-BuildReport -BuildResults $results
        $artifactsPath = Export-BuildArtifacts -BuildResults $results
        
        Send-NotificationAlert -BuildResults $results
        
        $successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
        $failureCount = ($results | Where-Object { $_.Status -eq "Failed" }).Count
        
        Write-LogMessage -Message "Pipeline execution completed. Success: $successCount, Failed: $failureCount" -Level "Info"
        Write-LogMessage -Message "Report generated: $reportPath" -Level "Info"
        Write-LogMessage -Message "Artifacts exported: $artifactsPath" -Level "Info"
        
        if ($failureCount -gt 0) {
            Write-LogMessage -Message "Pipeline completed with failures" -Level "Warning"
            exit 1
        } else {
            Write-LogMessage -Message "Pipeline completed successfully" -Level "Success"
            exit 0
        }
    } else {
        Write-LogMessage -Message "No build results generated" -Level "Warning"
        exit 1
    }
}
catch {
    Write-LogMessage -Message "Script execution failed: $_" -Level "Error"
    Write-LogMessage -Message "Stack trace: $($_.ScriptStackTrace)" -Level "Error"
    exit 1
}
finally {
    Clear-BuildCache
    Write-LogMessage -Message "CI/CD DevOps Integration Script completed" -Level "Info"
}
