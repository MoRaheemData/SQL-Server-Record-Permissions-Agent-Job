use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_RecordRevokedInstancePermissions] ( @JobLastRunDateTime datetime )
as
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000)
;

begin try

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of revoked instance permissions.';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	/* Insert revoked instance permissions in [RevokedInstancePermissions] table based on absence of existence 
		from current snapshot ([Staging_InstanceLevel]) compared to live table ([InstanceLevel]) */   
	insert [security_audit].[RevokedInstancePermissions] ([ServerName],[Scope],[sid],[PrincipalName],[PrincipalType],[IsDisabled],[PermissionType],[PermissionState],[ClassDescription],[EndpointName])
	select
		[ServerName],
		[Scope],
		[sid],
		[PrincipalName],
		[PrincipalType],
		[IsDisabled],
		[PermissionType],
		[PermissionState],
		[ClassDescription],
		[EndpointName]   
	from
		[security_audit].[InstanceLevel]
	except
	select
		[ServerName],
		[Scope],
		[sid],
		[PrincipalName],
		[PrincipalType],
		[IsDisabled],
		[PermissionType],
		[PermissionState],
		[ClassDescription],
		[EndpointName]
	from
		[security_audit].[Staging_InstanceLevel];

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of revoked instance permissions. Starting to delete revoked instance permissions from live table ([security_audit].[InstanceLevel]).';
	raiserror('%s',0,1,@OutputMessage) with nowait;
			
	/* Delete dropped principal from live table */   
	delete [security_audit].[InstanceLevel]   
	from     
		[security_audit].[InstanceLevel] i    
		inner join [security_audit].[RevokedInstancePermissions] d     
			on d.[ServerName] = i.[ServerName]
			and d.[Scope] = i.[Scope]
			and d.[sid] = i.[sid]
			and d.[PrincipalName] = i.[PrincipalName]
			and d.[PrincipalType] = i.[PrincipalType]
			and d.[IsDisabled] = i.[IsDisabled]
			and d.[PermissionType] = i.[PermissionType]
			and d.[PermissionState] = i.[PermissionState]
			and d.[ClassDescription] = i.[ClassDescription]
			and d.[EndpointName] = i.[EndpointName]
	where
		i.[PermissionType] != 'CONNECT SQL' /* Keep the principal itself in the [security_audit].[InstanceLevel] table, it will be removed in the "Record Dropped Server Principals" step */
		and d.PollDate > @JobLastRunDateTime; /* Permissions can be applied and revoked and reapplied and so on multiple times, so only join on where PollDate > @JobLastRunDateTime */

	commit;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished deleting revoked instance permissions from live table ([security_audit].[InstanceLevel]).';
	raiserror('%s',0,1,@OutputMessage) with nowait;
		
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