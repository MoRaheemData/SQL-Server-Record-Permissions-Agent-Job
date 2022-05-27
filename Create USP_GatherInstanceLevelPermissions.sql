use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_GatherInstanceLevelPermissions]
as
begin

set nocount on;

declare @ErrorMessage varchar(4000);

begin try
	
	/* insert current snapshot of instance level permissions into staging table [Staging_InstanceLevel] */
	insert [security_audit].[Staging_InstanceLevel] (ServerName,Scope,[sid],PrincipalName,PrincipalType,IsDisabled,PermissionType,PermissionState,ClassDescription,EndpointName)
	SELECT
		@@servername AS [ServerName],
		'Instance-Level' AS [Scope],
		prin.[sid] AS [sid],
		prin.[name] AS [PrincipalName],
		prin.[type_desc] AS [PrincipalType],
		CASE prin.[is_disabled] 
			WHEN 0 THEN 'No'     
			WHEN 1 THEN 'Yes'     
			ELSE '???'    
		END AS [IsDisabled],     
		perm.[permission_name] AS [PermissionType],     
		perm.[state_desc] AS [PermissionState],     
		perm.[class_desc] AS [ClassDescription],     
		COALESCE(e.[name], prin1.[name], 'N/A') AS [EndpointName]   
	FROM     
		[master].[sys].[server_principals] AS prin    
		JOIN [master].[sys].[server_permissions] AS perm      
			ON perm.[grantee_principal_id] = prin.[principal_id]    
		LEFT JOIN [master].[sys].[endpoints] AS e     
			ON e.[endpoint_id] = perm.[major_id]    
		LEFT OUTER JOIN [master].[sys].[server_principals] prin1     
			ON prin1.[principal_id] = perm.[major_id]     
			
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],    
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'sysadmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[sysadmin] = 1      
	
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'securityadmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[securityadmin] = 1      
		
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'serveradmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[serveradmin] = 1      
	
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'setupadmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[setupadmin] = 1      
		
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'processadmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[processadmin] = 1      
		
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'diskadmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[diskadmin] = 1      
		
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'dbcreator' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[dbcreator] = 1      
	
	UNION ALL      
	
	SELECT     
		@@servername AS [ServerName],     
		'Instance-Level' AS [Scope],    
		[sid] AS [sid],    
		[name] AS [PrincipalName],    
		CASE      
			WHEN [isntgroup] = 1 THEN 'WINDOWS_GROUP'     
			WHEN [isntuser] = 1 THEN 'WINDOWS_LOGIN'     
			WHEN [isntname] = 0 THEN 'SQL_LOGIN'    
		END AS [PermissionType],     
		CASE [status]     
			WHEN 9 THEN 'No'     
			ELSE 'Yes'    
		END AS [IsDisabled],     
		'Database Role' AS [PermissionType],     
		'GRANT' AS [PermissionState],     
		'SERVER' AS [ClassDescription],    
		'bulkadmin' AS [EndpointName]   
	FROM     
		[master].[sys].[syslogins]   
	WHERE    
		[bulkadmin] = 1  
	
end try  
begin catch  

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) + N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;  

end catch

end