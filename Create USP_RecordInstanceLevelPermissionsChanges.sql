use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_RecordInstanceLevelPermissionsChanges]
as
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000)
;

begin try

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting to capture differences between current extract and last snapshot (live table).';
	raiserror('%s',0,1,@OutputMessage) with nowait;

	drop table if exists #InstanceLevel;
	create table #InstanceLevel (
		ServerName varchar(257),   
		Scope varchar(128),    
		[sid] varbinary(85),    
		PrincipalName varchar(128),    
		PrincipalType varchar(50),    
		IsDisabled varchar(3),    
		PermissionType varchar(128),    
		PermissionState varchar(5),    
		ClassDescription varchar(20),    
		EndpointName varchar(128),   
	);
	
	begin tran
	
	/* Grab differences between current extract and last snapshot */   
	insert #InstanceLevel (ServerName,Scope,[sid],PrincipalName,PrincipalType,IsDisabled,PermissionType,PermissionState,ClassDescription,EndpointName)
	select
		ServerName,
		Scope,
		[sid],
		PrincipalName,
		PrincipalType,
		IsDisabled,
		PermissionType,
		PermissionState,
		ClassDescription,
		EndpointName
	from 
		[security_audit].[Staging_InstanceLevel]
	except
	select
		ServerName,
		Scope,
		[sid],
		PrincipalName,
		PrincipalType,
		IsDisabled,
		PermissionType,
		PermissionState,
		ClassDescription,
		EndpointName
	from 
		[security_audit].[InstanceLevel];

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished capturing differences between current extract and last snapshot (live table). Starting to update any changes.';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	/* Update - 
		These are the only things that will "change" for a given SID are - PrincipalName, IsDisabled, PermissionState.
			*/   
	update [security_audit].[InstanceLevel]
	set
		ServerName = t.ServerName,
		Scope = t.Scope,
		[sid] = t.[sid],
		PrincipalName = t.PrincipalName,
		PrincipalType = t.PrincipalType,
		IsDisabled = t.IsDisabled,
		PermissionType = t.PermissionType,
		PermissionState = t.PermissionState,
		ClassDescription = t.ClassDescription,
		EndpointName = t.EndpointName,
		PollDate = getdate()
	from     
		[security_audit].[InstanceLevel] i    
		inner join #InstanceLevel t     
			on i.ServerName = t.ServerName
			and i.Scope = t.Scope
			and i.[sid] = t.[sid]
			and i.PrincipalType = t.PrincipalType
			and i.PermissionType = t.PermissionType
			and i.ClassDescription = t.ClassDescription
			and i.EndpointName = t.EndpointName;      

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished updating any changes. Starting to delete matching records from temp table, leaving only the new permissions.';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	delete #InstanceLevel   
	from 
		#InstanceLevel t   
		inner join [security_audit].[InstanceLevel] i    
			on i.ServerName = t.ServerName
			and i.Scope = t.Scope
			and i.[sid] = t.[sid]
			and i.PrincipalName = t.PrincipalName
			and i.PrincipalType = t.PrincipalType
			and i.IsDisabled = t.IsDisabled
			and i.PermissionType = t.PermissionType
			and i.PermissionState = t.PermissionState
			and i.ClassDescription = t.ClassDescription
			and i.EndpointName = t.EndpointName;    

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished deleting matching records from temp table. Starting to insert new permissions in live table ([security_audit].[InstanceLevel]).';
	raiserror('%s',0,1,@OutputMessage) with nowait;
			
	/* Insert */   
	insert [security_audit].[InstanceLevel] (ServerName,Scope,[sid],PrincipalName,PrincipalType,IsDisabled,PermissionType,PermissionState,ClassDescription,EndpointName)   
	select     
		ServerName,
		Scope,
		[sid],
		PrincipalName,
		PrincipalType,
		IsDisabled,
		PermissionType,
		PermissionState,
		ClassDescription,
		EndpointName   
	from     
		#InstanceLevel;      
		
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished inserting new permissions in live table ([security_audit].[InstanceLevel]).';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	/* clean up */
	drop table if exists #InstanceLevel;  

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

	/* clean up */
	drop table if exists #InstanceLevel;  

end catch

end