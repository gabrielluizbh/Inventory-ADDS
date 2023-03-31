## Script de levantamento de informações do Active Directory - Créditos Gabriel Luiz - www.gabrielluiz.com #



# Script informa quais são os controladores de domínio (Domain Controllers), Site, Subnets, Relação de confiança, GPO, usuários e computadores que loga e não loga 90 dias, todos os usuários e computadores, mestre de operações (FSMO) e informações da floresta e domínio.


##################################################################  Ferramenta RSAT  ######################################################################

# Necessáiro para excução do script.

<#

Windows Cliente

Se estiver utilziando o Windows 10 - Versão 1809 ou posterior, Windows 11. Dúvidas sobre como instalar as Ferramentas de RSAT em versões mais nova do Windows Cliente leia este artigo: https://gabrielluiz.com/2020/04/rsat-windows-10-versao-1809/

#>


Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 # Instala da Ferramentas de Administração de Servidor Remoto: Active Directory Domain Services e Lightweight Directory Services Tools

Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 # Instala a Ferramentas de Gerenciamento de Política de Grupo.

Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State # Verificar a instalação.


<#

Windows Server

Recomendo o uso do Windows Server 2012 ou posterior.

#>


Install-WindowsFeature RSAT-ADDS # Instala da Ferramentas de Administração de Servidor Remoto: Active Directory Domain Services e Lightweight Directory Services Tool.

Install-WindowsFeature GPMC # Instala a Ferramentas de Gerenciamento de Política de Grupo.

Get-WindowsFeature| ft Name,Installstate # Verificar a instalação.





##################################################################  CRIAÇÃO DAS PASTAS  ######################################################################



# Cria as pasta para execução do levantamento de informações do Active Directory usando o nome do domínio.


$nome=@(get-addomain | select-object forest).forest


New-Item -Path "c:\Levantamento ADDS $nome" -ItemType directory


New-Item -Path "c:\Levantamento ADDS $nome\GPOs" -ItemType directory



##################################################################  DOMAIN CONTROLLERS  ######################################################################


# Importa o modulo AD

Import-Module ActiveDirectory


 
# Obtém o domínio do Active Directory.

$DomainName = (Get-ADDomain).DNSRoot


 
# Obtém o todos os controladores de domínio.

Get-ADDomainController -Filter * -Server $DomainName | Select Hostname, Ipv4address, isGlobalCatalog, Site, Forest, OperatingSystem | export-csv -path "c:\Levantamento ADDS $nome\Domain-Controllers.csv"



################################################################## FSMO - MESTRES DE OPERAÇÕES - Domínio ######################################################################



Get-ADDomain | Select-Object InfrastructureMaster,PDCEmulator,RIDMaster,DomainMode | export-csv -path "c:\Levantamento ADDS $nome\Domínio.csv"



################################################################## INFORMAÇÕES DA FLORESTA ######################################################################


Get-ADForest | Select-Object DomainNamingMaster,SchemaMaster,RootDomain, ForestMode | export-csv -path "c:\Levantamento ADDS $nome\Floresta.csv"



##################################################################  GPO   ######################################################################



# Carregar o módulo GroupPolicy.

Import-Module GroupPolicy


# Exportar GPO's para um relatório HTML.

Get-GPOReport -All -ReportType html -Path "c:\Levantamento ADDS $nome\GPOs\GposReport.html"



# Exportar cada GPO para seu próprio relatório HTML.


Get-GPO -All | select-object DisplayName,DomainName,GpoStatus,CreationTime,ModificationTime,Id,WmiFilter,Owner | export-csv -path "c:\Levantamento ADDS $nome\GPOs\GPO-All.csv" -Encoding UTF8



# Encontra as GPO's com todas as configurações desativadas.


$reportFile = "c:\Levantamento ADDS $nome\GPOs\AllSettingsDisabledGpos.csv"
Set-Content -Path $reportFile -Value ("GPO Name,Settings")
Get-GPO -All | where{ $_.GpoStatus -eq "AllSettingsDisabled" } | % {
    add-Content -Path $reportFile -Value ($_.displayName+","+$_.gpoStatus)
}


#  Gpo's que não se aplicam a ninguém, e aqueles que se aplicam descobrir para quem é.


$reportFile = "c:\Levantamento ADDS $nome\GPOs\GPOApplyToPermissions.csv"
Set-Content -Path $reportFile -Value ("GPO Name,User/Group,Denied")
Get-GPO -All | %{
    $gpoName = $_.displayName
    [int]$counter = 0
    $security = $_.GetSecurityInfo()
    $security | where{ $_.Permission -eq "GpoApply" } | %{
        add-Content -Path $reportFile -Value ($gpoName + "," + $_.trustee.name+","+$_.denied)
        $counter += 1
    }
    if ($counter -eq 0)
    {
        add-Content -Path $reportFile -Value ($gpoName + ",NOT APPLIED")
    }
}


# Obtenha GPO's, seus links e filtros WMI.

$reportFile = "c:\Levantamento ADDS $nome\GPOs\GPOLinksAndWMIFilters.csv"
Set-Content -Path $reportFile -Value ("GPO Name,# Links,Link Path,Enabled,No Override,WMI Filter")
$gpmc = New-Object -ComObject GPMgmt.GPM
$constants = $gpmc.GetConstants()
Get-GPO -All | %{
    [int]$counter = 0
    [xml]$report = $_.GenerateReport($constants.ReportXML)
    try
    {
        $wmiFilterName = $report.gpo.filtername
    }
    catch
    {
        $wmiFilterName = "none"
    }
    $report.GPO.LinksTo | % {
        if ($_.SOMPath -ne $null)
        {
            $counter += 1
            add-Content -Path $reportFile -Value ($report.GPO.Name + "," + $report.GPO.linksto.Count + "," + $_.SOMPath + "," + $_.Enabled + "," + $_.NoOverride + "," + $wmiFilterName)
        }
    }
    if ($counter -eq 0)
    {
        add-Content -Path $reportFile -Value ($report.GPO.Name + "," + $counter + "," + "NO LINKS" + "," + "NO LINKS" + "," + "NO LINKS")
    }
}



##################################################################  SITES E SUBNETS DO ACTIVE DIRECTORY  #########################################################################


## Obtenha uma lista de todos os controladores de domínio na floresta

$DcList = (Get-ADForest).Domains | ForEach { Get-ADDomainController -Discover -DomainName $_ } | ForEach { Get-ADDomainController -Server $_.Name -filter * } | Select Site, Name, Domain


## Obtenha todas as sub-redes de replicação de sites e serviços


$Subnets = Get-ADReplicationSubnet -filter * -Properties * | Select Name, Site, Location, Description


## Crie uma matriz vazia para criar a lista de sub-redes

$ResultsArray = @()



## Percorra todas as sub-redes e crie a lista

ForEach ($Subnet in $Subnets) {

    $SiteName = ""
    If ($Subnet.Site -ne $null) { $SiteName = $Subnet.Site.Split(',')[0].Trim('CN=') }

    $DcInSite = $False
    If ($DcList.Site -Contains $SiteName) { $DcInSite = $True }

    $RA = New-Object PSObject
    $RA | Add-Member -type NoteProperty -name "Subnet"   -Value $Subnet.Name
    $RA | Add-Member -type NoteProperty -name "SiteName" -Value $SiteName
    $RA | Add-Member -type NoteProperty -name "DcInSite" -Value $DcInSite
    $RA | Add-Member -type NoteProperty -name "SiteLoc"  -Value $Subnet.Location
    $RA | Add-Member -type NoteProperty -name "SiteDesc" -Value $Subnet.Description

    $ResultsArray += $RA

}

## Exporte a matriz como um arquivo CSV



$ResultsArray | Sort Subnet | Export-Csv "c:\Levantamento ADDS $nome\sites.csv" -Encoding UTF8



##################################################################  RELAÇÃO DE CONFIANÇA DO ACTIVE DIRECTORY  ##################################################################


Get-ADTrust -Filter * -Properties * | Select Name, Direction, Target, Source | Export-Csv "c:\Levantamento ADDS $nome\ADTrust.csv" -Encoding UTF8




################################################################## USUÁRIOS QUE LOGA E NÃO LOGA NO DOMÍNIO  ####################################################################

# Quem não loga a X dias.


$lastdate = (Get-Date).AddDays(-90)
$filter = {lastLogon -le $lastdate}
Get-AdUser -Filter $filter -Properties lastlogondate, DisplayName, Mail, CanonicalName, Enabled | select name, UserPrincipalName, lastlogondate, Enabled, DisplayName, mail, CanonicalName | Export-Csv "c:\Levantamento ADDS $nome\naologa90dias.csv" -Encoding UTF8


# Quem loga a X dias.


$lastdate = (Get-Date).AddDays(-90)
$filter = {lastLogon -ge $lastdate}
Get-AdUser -Filter $filter -Properties lastlogondate, DisplayName, Mail, CanonicalName, Enabled | select name, UserPrincipalName, lastlogondate, Enabled, DisplayName, mail, CanonicalName | Export-Csv "c:\Levantamento ADDS $nome\logaa90dias.csv" -Encoding UTF8



# Todos os usuários


Get-AdUser -Filter * -Properties lastlogondate, DisplayName, Mail, CanonicalName, Enabled, description, department, company, physicalDeliveryOfficeName | select name, UserPrincipalName, lastlogondate, Enabled, description, department, DisplayName, company, physicalDeliveryOfficeName, mail, CanonicalName | Export-Csv "c:\Levantamento ADDS $nome\todoosusuarios.csv" -Encoding UTF8


################################################################## COMPUTADORES QUE LOGA E NÃO LOGA NO DOMÍNIO  ####################################################################


# Computadores que não loga a X dias.


$lastdate = (Get-Date).AddDays(-90)
$filter = {PasswordLastSet -le $lastdate}
Get-ADComputer -Filter $filter -Properties Name, PasswordLastSet, OperatingSystem, DNSHostName, DistinguishedName, Enabled  | select Name, PasswordLastSet, OperatingSystem, DNSHostName, DistinguishedName, Enabled | Export-Csv "c:\Levantamento ADDS $nome\computadoresnaologa90dias.csv" -Encoding UTF8



# Computador que loga a X dias.

$lastdate = (Get-Date).AddDays(-90)
$filter = {PasswordLastSet -ge $lastdate}
Get-ADComputer -Filter $filter -Properties Name, PasswordLastSet, OperatingSystem, DNSHostName, DistinguishedName, Enabled | select Name, PasswordLastSet, OperatingSystem, DNSHostName, DistinguishedName, Enabled | Export-Csv "c:\Levantamento ADDS $nome\computadorquelogaa90dias.csv" -Encoding UTF8



# Todos os computadores

Get-ADComputer -Filter * -Properties Name, PasswordLastSet, OperatingSystem, operatingSystemVersion, DNSHostName, DistinguishedName, Enabled | select Name, PasswordLastSet, OperatingSystem, operatingSystemVersion, DNSHostName, DistinguishedName, Enabled | Export-Csv "c:\Levantamento ADDS $nome\todososcomputadores.csv" -Encoding UTF8




################################################################## UOS VAZIAS  ####################################################################

Get-ADOrganizationalUnit -Filter * | ForEach-Object { If ( !( Get-ADObject -Filter * -SearchBase $_ -SearchScope OneLevel) ) { $_ } } | Select-Object Name, DistinguishedName | Export-Csv "c:\Levantamento ADDS $nome\OUsvazias.csv" -Encoding UTF8


<#

Referências:


https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.3&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-7.3&WT.mc_id=5003815
f
https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontroller?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adforest?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-7.3&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content?view=powershell-7.3&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationsubnet?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-member?view=powershell-7.3&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-csv?view=powershell-7.3&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date?view=powershell-7.3&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adorganizationalunit?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/dism/add-windowscapability?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/dism/get-windowscapability?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/servermanager/install-windowsfeature?view=windowsserver2022-ps&WT.mc_id=5003815

https://learn.microsoft.com/en-us/powershell/module/servermanager/get-windowsfeature?view=windowsserver2022-ps&WT.mc_id=5003815



#>
