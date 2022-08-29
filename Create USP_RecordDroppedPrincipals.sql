use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_RecordDroppedPrincipals] ( @JobLastRunDateTime datetime )
as
begin

set nocount on;

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000)
;

begin try
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of dropped principals.';
	raiserror('%s',0,1,@OutputMessage) with nowait;

	begin tran
	
	/* Insert dropped principals into [DroppedPrincipals] table based on absence of existence 
		from current snapshot ([Staging_InstanceLevel]) compared to live table ([InstanceLevel]) */
	insert [security_audit].[DroppedPrincipals] (ServerName,Scope,[sid],PrincipalName,PrincipalType)
	select
		ServerName,
		Scope,
		[sid],
		PrincipalName,
		PrincipalType
	from
		[security_audit].[InstanceLevel]
	except
	select
		ServerName,
		Scope,
		[sid],
		PrincipalName,
		PrincipalType
	from 
		[security_audit].[Staging_InstanceLevel];
	
	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of dropped principals. Starting to delete dropped principals from live table ([security_audit].[InstanceLevel]).';
	raiserror('%s',0,1,@OutputMessage) with nowait;

	/* Delete dropped principal from live table */   
	delete [security_audit].[InstanceLevel]
	from
		[security_audit].[InstanceLevel] i    
		inner join [security_audit].[DroppedPrincipals] d     
			on d.ServerName = i.ServerName
			and d.Scope = i.Scope
			and d.[sid] = i.[sid]
			and d.PrincipalName = i.PrincipalName
			and d.PrincipalType = i.PrincipalType;
	where
		d.PollDate > @JobLastRunDateTime;
	
	commit;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished deleting dropped principals from live table ([security_audit].[InstanceLevel]).';
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
