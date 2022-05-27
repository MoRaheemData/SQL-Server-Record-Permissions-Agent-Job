use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_RecordDatabaseObjectPermissionChanges]
as
begin

set nocount on;

declare @ErrorMessage varchar(4000);

begin try

	/* Insert */
	insert [security_audit].[DatabaseObjectLevel] ([ServerName],[Scope],[sid],[PrincipalName],[ObjectType],[PermissionType],[PermissionState],[SchemaName],[ObjectName],[ColumnName])
	select
		[ServerName],
		[Scope],
		[sid],
		[PrincipalName],
		[ObjectType],
		[PermissionType],
		[PermissionState],
		[SchemaName],
		[ObjectName],
		[ColumnName]
	from
		[security_audit].[Staging_DatabaseObjectLevel]
	except
	select
		[ServerName],
		[Scope],
		[sid],
		[PrincipalName],
		[ObjectType],
		[PermissionType],
		[PermissionState],
		[SchemaName],
		[ObjectName],
		[ColumnName]
	from
		[security_audit].[DatabaseObjectLevel];

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

end catch

end