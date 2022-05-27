use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_GatherDatabaseObjectPermissions]
as
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000),
	@DatabaseName varchar(128),    
	@SQLStmt varchar(4000)
;

/* Populate temp table with valid database names to loop through */
drop table if exists #Database;
create table #Database (
	[DatabaseName] varchar(128),
	[IsProcessed] bit default 0
);      
	
insert #Database ([DatabaseName])   
select     
	[name]   
from     
	[master].sys.databases   
where    
	state_desc = 'ONLINE'    
	and user_access_desc = 'MULTI_USER';      

begin try   

	while exists (select 1 from #Database where [IsProcessed] = 0)   
	begin    
		select top 1     
			@DatabaseName = [DatabaseName]    
		from      
			#Database     
		where      
			[IsProcessed] = 0;       

		set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of database permissions in [' + @DatabaseName + ']';
		raiserror('%s',0,1,@OutputMessage) with nowait;

		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 0 = Database */    
		SELECT     @@SERVERNAME AS [ServerName],     
		''' + @DatabaseName + ''' AS [Scope],     
		prin.[sid] AS [sid],     
		prin.[name] AS [PrincipalName],    
		perm.[class_desc] AS [ObjectType],     
		perm.[permission_name] AS [PermissionType],     
		perm.[state_desc] AS [PermissionState],     
		''N/A'' AS [SchemaName],     
		''N/A'' AS [ObjectName],     
		''N/A'' AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin      
				ON prin.[principal_id] = perm.[grantee_principal_id]    
		WHERE     
			perm.[class] = 0 /* 0 = DATABASE */    
		;';    
		exec(@SQLStmt);        
		
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 1 = Object or Column */    
		SELECT     
		@@SERVERNAME AS [ServerName],     
		''' + @DatabaseName + '''  AS [Scope],     
		prin.[sid] AS [sid],     
		prin.[name] AS [PrincipalName],    
		ISNULL(obj.[type_desc], 
		perm.[class_desc]) AS [ObjectType],     
		perm.[permission_name] AS [PermissionType],     
		perm.[state_desc] AS [PermissionState],     
		ISNULL(s.[name], ''Unknown'') AS [SchemaName],     
		COALESCE(obj.[name], OBJECT_NAME(perm.[major_id]), ''N/A'') AS [ObjectName],     
		ISNULL(c.[name], ''N/A'') AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin      
				ON prin.[principal_id] = perm.[grantee_principal_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[all_objects] obj      
				ON obj.[object_id] = perm.[major_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[schemas] s      
				ON s.[schema_id] = obj.[schema_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[all_columns] c      
				ON c.[column_id] = perm.[minor_id]    
		WHERE     
			perm.[class] = 1 /* 1 = Object or Column */  
		;'    
		exec(@SQLStmt);       
		
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 3 = Schema */    
		SELECT     
			@@SERVERNAME AS [ServerName],     
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrincipalName],     
			perm.[class_desc] AS [ObjectType],     
			perm.[permission_name] AS [PermissionType],     
			perm.[state_desc] AS [PermissionState],     
			s.[name] AS [SchemaName],     
			''N/A'' AS [ObjectName],     
			''N/A'' AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin      
				ON prin.[principal_id] = perm.[grantee_principal_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[schemas] s      
				ON s.[schema_id] = perm.[major_id]    
			WHERE     
				perm.[class] = 3 /* 3 = Schema */    
			;';    exec(@SQLStmt);       
			
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 4 = DATABASE_PRINCIPAL */    
		SELECT     
			@@SERVERNAME AS [ServerName],     
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrincipalName],     
			perm.[class_desc] AS [ObjectType],     
			perm.[permission_name] AS [PermissionType],     
			perm.[state_desc] AS [PermissionState],     
			''N/A'' AS [SchemaName],     
			prin1.[name] AS [ObjectName],      
			''N/A'' AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin       
				ON prin.[principal_id] = perm.[grantee_principal_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin1      
				ON prin1.[principal_id] = perm.[major_id]    
		WHERE     
			perm.[class] = 4 /* 4 = DATABASE_PRINCIPAL */   
		;';    
		exec(@SQLStmt);       
		
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 5 = Assembly */    
		SELECT     
			@@SERVERNAME AS [ServerName],     
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrincipalName],     
			perm.[class_desc] AS [ObjectType],     
			perm.[permission_name] AS [PermissionType],     
			perm.[state_desc] AS [PermissionState],     
			''N/A'' AS [SchemaName],     
			USER_NAME(a.[name]) AS [ObjectName],     
			''N/A'' AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin      
				ON prin.[principal_id] = perm.[grantee_principal_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[assemblies] a      
				ON a.[principal_id] = perm.[major_id]    
		WHERE     
			perm.[class] = 5 /* 5 = Assembly */    
		;';    
		exec(@SQLStmt);       
		
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 6 = Type */    
		SELECT     
			@@SERVERNAME AS [ServerName],     
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrincipalName],     
			perm.[class_desc] AS [ObjectType],     
			perm.[permission_name] AS [PermissionType],     
			perm.[state_desc] AS [PermissionState],     
			''N/A'' AS [SchemaName],     
			t.[name] AS [ObjectName],     
			''N/A'' AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin      
				ON prin.[principal_id] = perm.[grantee_principal_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[types] t      
				ON t.[user_type_id] = perm.[major_id]    
		WHERE     
			perm.[class] = 6 /* 6 = Type */
		;';    
		exec(@SQLStmt);       
		
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 10 = XML Schema Collection */    
		SELECT      
			@@SERVERNAME AS [ServerName],     
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrincipalName],     
			perm.[class_desc] AS [ObjectType],     
			perm.[permission_name] AS [PermissionType],     
			perm.[state_desc] AS [PermissionState],     
			''N/A'' AS [SchemaName],     
			COALESCE(OBJECT_NAME(perm.[major_id]), ''Unknown'') AS [ObjectName],     
			''N/A'' AS [ColumnName]    		
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin       
				ON prin.[principal_id] = perm.[grantee_principal_id]    
		WHERE     
			perm.[class] = 10 /* 10 = XML Schema Collection Certificates */   
		;';    
		exec(@SQLStmt);       
		
		set @SQLStmt = '    
		insert [security_audit].[Staging_DatabaseObjectLevel] (ServerName,Scope,[sid],PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName)    
		/* [class] = 25 = Certificates */    
		SELECT      
			@@SERVERNAME AS [ServerName],     
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrincipalName],     
			perm.[class_desc] AS [ObjectType],     
			perm.[permission_name] AS [PermissionType],     
			perm.[state_desc] AS [PermissionState],     
			''N/A'' AS [SchemaName],     
			COALESCE(cer.[name], ''Unknown'') AS [ObjectName],     
			''N/A'' AS [ColumnName]    
		FROM     
			[' + @DatabaseName + '].[sys].[database_permissions] perm    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin      
				ON prin.[principal_id] = perm.[grantee_principal_id]    
			LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[certificates] cer      
				ON cer.[certificate_id] = perm.[major_id]    
		WHERE     
			perm.[class] = 25 /* 25 = Certificates */    
		;';    
		exec(@SQLStmt);        
		
		set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of database permissions in [' + @DatabaseName + ']';
		raiserror('%s',0,1,@OutputMessage) with nowait;

		update #Database    
		set     
			[IsProcessed] = 1     
		from      
			#Database     
		where      
			[DatabaseName] = @DatabaseName;   
		
	end      

	/* clean up*/   
	drop table if exists #Database;  

end try  
begin catch   
	
	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;  
	
	/* clean up*/   
	drop table if exists #Database;  

end catch

end