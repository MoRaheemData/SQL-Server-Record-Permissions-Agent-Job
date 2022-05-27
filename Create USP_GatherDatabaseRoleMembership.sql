use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_GatherDatabaseRoleMembership]
as
begin

set nocount on;    

declare 
	@ErrorMessage varchar(4000),
	@OutputMessage varchar(4000),
	@DatabaseName varchar(128),    
	@SQLStmt varchar(4000)
;

/* Populate temp table with valid database names to loop through */
drop table if exists #Database;   
create table #Database (    
	[DatabaseName] varchar(128),    
	[IsProcessed] bit default 0   
);      

insert #Database ([DatabaseName])   
select     
	[name]   
from     
	[master].sys.databases   
where    
	state_desc = 'ONLINE'    
	and user_access_desc = 'MULTI_USER';      

begin try   

	while exists (select 1 from #Database where [IsProcessed] = 0)   
	begin    
		select top 1     
			@DatabaseName = [DatabaseName]    
		from      
			#Database     
		where	
			[IsProcessed] = 0;       
		
		set @OutputMessage = convert(varchar, getdate(), 21) + ': Starting identification of database role mappings in [' + @DatabaseName + '].';
		raiserror('%s',0,1,@OutputMessage) with nowait;
	
		set @SQLStmt = '    
		insert [security_audit].[Staging_PrincipalToDatabaseRoleMappings](ServerName,Scope,[sid],PrincipalName,PrincipalType,DatabaseRole)    
		SELECT     
			@@SERVERNAME AS [ServerName],      
			''' + @DatabaseName + ''' AS [Scope],     
			prin.[sid] AS [sid],     
			prin.[name] AS [PrinicpalName],     
			prin.[type_desc] AS [PrincipalType],     
			prin1.[name] AS [DatabaseRole]    
		FROM      
			[' + @DatabaseName + '].[sys].[database_principals] prin     
			INNER JOIN [' + @DatabaseName + '].[sys].[database_role_members] mem      
				ON mem.[member_principal_id] = prin.[principal_id]     
			INNER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin1      
				ON prin1.[principal_id] = mem.[role_principal_id]    
		';    
		exec(@SQLStmt);        
		
		set @OutputMessage = convert(varchar, getdate(), 21) + ': Finished identification of database role mappings in [' + @DatabaseName + '].';
		raiserror('%s',0,1,@OutputMessage) with nowait;
			
		update #Database    
		set     
			[IsProcessed] = 1     
		from      
			#Database     
		where      
			[DatabaseName] = @DatabaseName;   	
	end

	/* clean up */
	drop table if exists #Database

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
		
	/* clean up */
	drop table if exists #Database

end catch

end