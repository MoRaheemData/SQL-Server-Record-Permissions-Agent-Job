use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_RecordADGroupMembershipChanges]
as
begin

set nocount on;

declare @ErrorMessage varchar(4000);

begin try
	/* Update not needed because both attributes make up the PK */
	
	/* Insert */
	insert [security_audit].[PrincipalToADGroupMappings] ([sid],[PrincipalName],[ADGroupName])
	select
		[sid],
		[PrincipalName],
		[ADGroupName]
	from
		[security_audit].[Staging_PrincipalToADGroupMappings]
	except
	select
		[sid],
		[PrincipalName],
		[ADGroupName]
	from
		[security_audit].[PrincipalToADGroupMappings];

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