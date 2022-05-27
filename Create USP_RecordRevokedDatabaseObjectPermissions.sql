use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_RecordRevokedDatabaseObjectPermissions] ( @JobLastRunDateTime datetime )
as 
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000)
;

begin try   

	begin tran
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of revoked database permissions and inserting into table [security_audit].[RevokedDatabasePermissions].';
	raiserror('%s',0,1,@OutputMessage) with nowait;

	/* Insert revoked permissions based on absence of existence */   
	insert [security_audit].[RevokedDatabasePermissions] ([ServerName],[Scope],[sid],[PrincipalName],[ObjectType],[PermissionType],[PermissionState],[SchemaName],[ObjectName],[ColumnName])   
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
		[security_audit].[DatabaseObjectLevel]   
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
		[security_audit].[Staging_DatabaseObjectLevel];      
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of revoked database permissions. Deleting revoked permissions from live table [security_audit].[DatabaseObjectLevel].';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	/* Delete revoked permissions from table */   
	delete [security_audit].[DatabaseObjectLevel]
	from 
		[security_audit].[DatabaseObjectLevel] i    
		inner join [security_audit].[RevokedDatabasePermissions] d     
			on d.[ServerName] = i.[ServerName]     
			and d.Scope = i.Scope     
			and d.[sid] = i.[sid]     
			and d.[PrincipalName] = i.[PrincipalName]     
			and d.[ObjectType] = i.[ObjectType]     
			and d.[PermissionType] = i.[PermissionType]     
			and d.[PermissionState] = i.[PermissionState]     
			and d.[SchemaName] = i.[SchemaName]     
			and d.[ObjectName] = i.[ObjectName]     
			and d.[ColumnName] = i.[ColumnName]
			and d.PollDate > @JobLastRunDateTime; /* Permissions can be applied and revoked and reapplied and so on multiple times, so only join on where PollDate > @JobLastRunDateTime */

	commit;

end try  
begin catch   
	
	rollback;

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