use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_RecordPermissions_Master]
as
begin

set nocount on;

/* Declare needed variables */
declare 
	@JobLastRunDate char(8), /* Needed for @JobLastRunDateTime_Formatted */
	@JobLastRunTime char(6), /* Needed for @JobLastRunDateTime_Formatted */
	@JobLastRunDateTime_Formatted char(23), /* Used for storing datetime format of last successful execution of the 'ADMIN - Record Permissions' SQL Agent job */
	@RecordPermissionsAuditID int, /* Used for logging to audit table */
	@NestedUSPAuditID int, /* Used for logging to audit table */
	@OutputMessage varchar(4000),
	@ErrorMessage varchar(max)
;

/* Log to audit table that USP_RecordPermissions_Master has been executed */
insert [security_audit].[RecordPermissionsAudit] ([USPName])
values 
	('USP_RecordPermissions_Master');
	
select @RecordPermissionsAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */

/* select run date & time of last successful run */
select top 1
	@JobLastRunDate = convert(char(8),sjh.run_date),
	@JobLastRunTime = right('000000'+cast(sjh.run_time as varchar(6)),6) /* format run_time (int) with leading 0's */
from 
	msdb.dbo.sysjobhistory sjh
	inner join msdb.dbo.sysjobs j
		on j.job_id = sjh.job_id
where
	j.[name] = 'ADMIN - Record Permissions'
	and sjh.step_id = 0 /* Job outcome */
	and sjh.run_status = 1
order by 
	sjh.run_date desc,
	run_time desc;

/* Format last successful run date & time (int's) to datetime */
set @JobLastRunDateTime_Formatted = 
	/* Format @JobLastRunDate int to 'YYYY-MM-DD' */
	substring(cast(@JobLastRunDate as char(8)), 1, 4) + '-' + substring(cast(@JobLastRunDate as char(8)), 5, 2) + '-' + substring(cast(@JobLastRunDate as char(8)), 7, 2)
	+ ' ' +
	/* Format @JobLastRunTime int to 'HH:MM:SS.000' */
	substring(cast(@JobLastRunTime as char(6)), 1, 2) + ':' + substring(cast(@JobLastRunTime as char(6)), 3, 2) + ':' + substring(cast(@JobLastRunTime as char(6)), 5, 2) + '.000';

/* 
	Start message 
*/
set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting execution of nested stored procedures... Using @LastRunDateTime of: ' + convert(varchar,@JobLastRunDateTime_Formatted);
raiserror('%s',0,1,@OutputMessage) with nowait;

/*
	Step 1 - Truncate Staging Tables
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_TruncateStagingTables');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 1 - Truncate Staging Tables'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_TruncateStagingTables];
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 1 - Truncate Staging Tables'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 1 - Truncate Staging Tables'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;  
end catch

/*
	Step 2 - Gather Instance Level Permissions - Staging
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_GatherInstanceLevelPermissions');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 2 - Gather Instance Level Permissions - Staging'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_GatherInstanceLevelPermissions];
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 2 - Gather Instance Level Permissions - Staging'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 2 - Gather Instance Level Permissions - Staging'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;  
end catch

/*
	Step 3 - Record Revoked Instance Permissions
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordRevokedInstancePermissions');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 3 - Record Revoked Instance Permissions'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordRevokedInstancePermissions] @JobLastRunDateTime_Formatted;
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 3 - Record Revoked Instance Permissions'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 3 - Record Revoked Instance Permissions'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;  
end catch

/*
	Step 4 - Record Dropped Server Principals
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordDroppedPrincipals');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 4 - Record Dropped Server Principals'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordDroppedPrincipals] @JobLastRunDateTime_Formatted;
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 4 - Record Dropped Server Principals'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 4 - Record Dropped Server Principals'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 5 - Record Instance Level Permissions Changes - Upsert
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordInstanceLevelPermissionsChanges');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 5 - Record Instance Level Permissions Changes - Upsert'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordInstanceLevelPermissionsChanges];
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 5 - Record Instance Level Permissions Changes - Upsert'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 5 - Record Instance Level Permissions Changes - Upsert'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 6 - Gather AD Group Membership - Staging
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_GatherADGroupMembership');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 6 - Gather AD Group Membership - Staging'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_GatherADGroupMembership];
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 6 - Gather AD Group Membership - Staging'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 6 - Gather AD Group Membership - Staging'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 7 - Record Dropped Members From AD Groups
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordDroppedMembersFromADGroups');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 7 - Record Dropped Members From AD Groups'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordDroppedMembersFromADGroups] @JobLastRunDateTime_Formatted;
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 7 - Record Dropped Members From AD Groups'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 7 - Record Dropped Members From AD Groups'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 8 - Record AD Group Membership Changes - Upsert
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordADGroupMembershipChanges');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 8 - Record AD Group Membership Changes - Upsert'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordADGroupMembershipChanges];
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 8 - Record AD Group Membership Changes - Upsert'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 8 - Record AD Group Membership Changes - Upsert'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 9 - Gather Database Role Membership - Staging
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_GatherDatabaseRoleMembership');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 9 - Gather Database Role Membership - Staging'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	exec [security_audit].[USP_GatherDatabaseRoleMembership];
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 9 - Gather Database Role Membership - Staging'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 9 - Gather Database Role Membership - Staging'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 10 - Record Dropped Database Role Membership
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordDroppedDatabaseRoleMembership');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 10 - Record Dropped Database Role Membership'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordDroppedDatabaseRoleMembership] @JobLastRunDateTime_Formatted;
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 10 - Record Dropped Database Role Membership'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 10 - Record Dropped Database Role Membership'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 11 - Record Dropped Database Role Membership
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordDatabaseRoleMembershipChanges');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 11 - Record Database Role Membership Changes - Upsert'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordDatabaseRoleMembershipChanges];
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 11 - Record Database Role Membership Changes - Upsert'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 11 - Record Database Role Membership Changes - Upsert'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 12 - Gather Database Object Permissions - Staging
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_GatherDatabaseObjectPermissions');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 12 - Gather Database Object Permissions - Staging'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	exec [security_audit].[USP_GatherDatabaseObjectPermissions];
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 12 - Gather Database Object Permissions - Staging'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 12 - Gather Database Object Permissions - Staging'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 13 - Record Revoked Database Object Permissions
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordRevokedDatabaseObjectPermissions');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 13 - Record Revoked Database Object Permissions'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	begin tran

	exec [security_audit].[USP_RecordRevokedDatabaseObjectPermissions] @JobLastRunDateTime_Formatted;
	
	commit

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 13 - Record Revoked Database Object Permissions'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 13 - Record Revoked Database Object Permissions'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/*
	Step 14 - Record Database Object Permission Changes - Upsert
*/
begin try
	insert [security_audit].[RecordPermissionsAudit] ([ParentAuditID],[USPName])
	values 
		(@RecordPermissionsAuditID,'USP_RecordDatabaseObjectPermissionChanges');
	
	select @NestedUSPAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 14 - Record Database Object Permission Changes - Upsert'' starting...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	exec [security_audit].[USP_RecordDatabaseObjectPermissionChanges];
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 14 - Record Database Object Permission Changes - Upsert'' completed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;
end try
begin catch
	rollback;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': ''Step 14 - Record Database Object Permission Changes - Upsert'' failed...';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'N'
	where
		[RecordPermissionsAuditID] = @NestedUSPAuditID;

	SET @ErrorMessage = 
		convert(varchar, getdate(), 21)     
		+ N': An ERROR occurred {Message=' + ERROR_MESSAGE()     
		+ N'}; {Number=' + CAST(ERROR_NUMBER() AS VARCHAR(MAX))     
		+ N'}; {Severity=' + CAST(ERROR_SEVERITY() AS VARCHAR(MAX))    
		+ N'}; {State=' + CAST(ERROR_STATE() AS VARCHAR(MAX)) 
		+ N'}';   
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
end catch

/* 
	Update Audit table & print All Completed message 
*/
update [security_audit].[RecordPermissionsAudit]
set
	[ExecStopDT] = getdate(),
	[SuccessIndicator] = 'Y'
where
	[RecordPermissionsAuditID] = @RecordPermissionsAuditID;

set @OutputMessage = convert(varchar, getdate(), 21) + ': All steps completed...';
raiserror('%s',0,1,@OutputMessage) with nowait;

end
