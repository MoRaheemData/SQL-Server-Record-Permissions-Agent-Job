use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_RecordDroppedMembersFromADGroups] ( @JobLastRunDateTime datetime )
as
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000)
;

begin try
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of dropped AD Group members and inserting into [security_audit].[DroppedMembersFromADGroups].';
	raiserror('%s',0,1,@OutputMessage) with nowait;

	begin tran

	/* Insert dropped AD Group members based on absence of existence */   
	insert [security_audit].[DroppedMembersFromADGroups] ([sid],PrincipalName,ADGroupName)   
	select
		[sid],
		[PrincipalName],
		[ADGroupName]   
	from
		[security_audit].[PrincipalToADGroupMappings]   
	except
	select
		[sid],
		[PrincipalName],
		[ADGroupName]   
	from     
		[security_audit].[Staging_PrincipalToADGroupMappings];      
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of dropped AD Group members. Starting to delete dropped AD Group members from [security_audit].[PrincipalToADGroupMappings].';
	raiserror('%s',0,1,@OutputMessage) with nowait;
		
	/* Delete dropped AD Group member mappings from table */   
	delete [security_audit].[PrincipalToADGroupMappings]   
	from     
		[security_audit].[PrincipalToADGroupMappings] i    
		inner join [security_audit].[DroppedMembersFromADGroups] d
			on isnull(d.[sid],0) = isnull(i.[sid],0)     
			and d.PrincipalName = i.PrincipalName     
			and d.ADGroupName = i.ADGroupName
			and d.PollDate > @JobLastRunDateTime; /* Membership can be added and removed and added and so on multiple times, so only join on where PollDate > @JobLastRunDateTime */
	
	commit;
		
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished deleting dropped AD Group members from [security_audit].[PrincipalToADGroupMappings].';
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