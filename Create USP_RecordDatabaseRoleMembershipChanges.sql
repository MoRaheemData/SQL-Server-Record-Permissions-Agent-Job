use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_RecordDatabaseRoleMembershipChanges]
as
begin

set nocount on;

declare @ErrorMessage varchar(4000);

begin try

	/* Update not needed because a principal either is or is not a member of a role */      
	
	/* Insert */   
	insert [security_audit].[PrincipalToDatabaseRoleMappings] (ServerName,Scope,[sid],PrincipalName,PrincipalType,DatabaseRole)   
	select     
		ServerName,    
		Scope,    
		[sid],    
		PrincipalName,    
		PrincipalType,    
		DatabaseRole   
	from     
		[security_audit].[Staging_PrincipalToDatabaseRoleMappings]   
	except   
	select     
		ServerName,    
		Scope,    
		[sid],    
		PrincipalName,    
		PrincipalType,    
		DatabaseRole   
	from     
		[security_audit].[PrincipalToDatabaseRoleMappings];  

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