use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_RecordDroppedDatabaseRoleMembership] ( @JobLastRunDateTime datetime )
as
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000)
;

begin try   

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of changes in database role membership, and inserting into table [security_audit].[DroppedMembersFromDatabaseRoles].';
	raiserror('%s',0,1,@OutputMessage) with nowait;

	begin tran

	/* Insert dropped database role members based on absence of existence */   
	insert [security_audit].[DroppedMembersFromDatabaseRoles] (ServerName,Scope,[sid],PrincipalName,PrincipalType,DatabaseRole)   
	select     
		ServerName,    
		Scope,    
		[sid],    
		PrincipalName,    
		PrincipalType,    
		DatabaseRole   
	from     
		[security_audit].[PrincipalToDatabaseRoleMappings]   
	except   
	select     
		ServerName,    
		Scope,    
		[sid],    
		PrincipalName,    
		PrincipalType,    
		DatabaseRole   
	from     
		[security_audit].[Staging_PrincipalToDatabaseRoleMappings];      
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of changes in database role membership. Starting to delete dropped members from table [security_audit].[PrincipalToDatabaseRoleMappings].';
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	/* Delete dropped database role member mappings from table */   
	delete [security_audit].[PrincipalToDatabaseRoleMappings]   
	from     
		[security_audit].[PrincipalToDatabaseRoleMappings] i    
		inner join [security_audit].[DroppedMembersFromDatabaseRoles] d     
			on d.Scope = i.Scope     
			and d.[sid] = i.[sid]     
			and d.PrincipalName = i.PrincipalName     
			and d.PrincipalType = i.PrincipalType    
			and d.DatabaseRole = i.DatabaseRole
			and d.PollDate > @JobLastRunDateTime; /* Membership can be added and removed and added and so on multiple times, so only join on where PollDate > @JobLastRunDateTime */

	commit;
		
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished deleting dropped members from table [security_audit].[PrincipalToDatabaseRoleMappings].';
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