use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_GatherADGroupMembership]
as
begin

set nocount on;    

declare @ErrorMessage varchar(4000);    

begin try   
	
	begin tran

	/* Gather all Windows Groups from syslogins */   
	DROP TABLE IF EXISTS #SysLogins;   
	CREATE TABLE #SysLogins (    
		[sid] varbinary(85),    
		[name] [varchar](128) NOT NULL,    
		[status] [varchar](8) NULL,    
		[isntgroup] [int] NULL,    
		[MemberOfGroup] [varchar](256) NULL   
	);       
	
	INSERT INTO #SysLogins ( [sid],[name],[status],[isntgroup] )   
	SELECT     
		[sid],    
		[name],    
		CASE [status]     
			WHEN 9 THEN 'Enabled'     
			WHEN 10 THEN 'Disabled'     
			ELSE '???'     
		END AS 'Status',    
		[isntgroup] /* 1 = Login is a Windows group */   
	FROM     
		[master].[sys].[syslogins]   
	WHERE     
		[isntgroup] = 1;       
		
	/* Gather all members of Windows Groups */   
	DROP TABLE IF EXISTS #NtGroup;   
	CREATE TABLE #NtGroup (    
		[name] [varchar](128) NOT NULL,    
		[IsProcessed] [BIT] DEFAULT 0    
	);       
	
	DROP TABLE IF EXISTS #ADGroupMember;    
	CREATE TABLE #ADGroupMember (     
		[account name] [varchar](128),    
		[type] [varchar](128),    
		[privilege] [varchar](128),    
		[mapped login name] [varchar](128),    
		[permission path] [varchar](128)   
	);       
	
	INSERT INTO #NtGroup ( [name] )   
	SELECT     
		[name]   
	FROM     
		#SysLogins;       
		
	WHILE EXISTS ( SELECT TOP 1 [name] FROM #NtGroup WHERE [IsProcessed] = 0 )   
	
	BEGIN    
	
	DECLARE @NtName [varchar](128);        
	
	SELECT TOP 1      
		@NtName = [name]    
	FROM      
		#NtGroup     
	WHERE      
		[IsProcessed] = 0;         
		
	INSERT INTO #ADGroupMember ( [account name], [type], [privilege], [mapped login name], [permission path] )    
	EXEC [master]..[xp_logininfo] @acctname = @NtName, @option = 'members';        
	
	UPDATE #NtGroup    
	SET      
		[IsProcessed] = 1    
	WHERE     
		[name] = @NtName;   
		
	END       
	
	INSERT INTO #SysLogins ( [name],[status],[isntgroup],[MemberOfGroup] )   
	SELECT     
		a.[account name],    
		s.[status],    
		s.[isntgroup],    
		a.[permission path]   
	FROM    
		#ADGroupMember a    
		LEFT OUTER JOIN #SysLogins s      
			ON s.[name] = a.[permission path];       
			
	DROP TABLE IF EXISTS #GroupLoop;   
	CREATE TABLE #GroupLoop (    
		[account name] [varchar](128),    
		[type] [varchar](128),    
		[privilege] [varchar](128),    
		[mapped login name] [varchar](128),    
		[permission path] [varchar](max),	
		[IsProcessed] [BIT] DEFAULT 0   
	);       
	
	INSERT INTO #GroupLoop ( [account name],[type],[privilege],[mapped login name],[permission path] )   
	SELECT     
		[account name],    
		[type],    
		[privilege],    
		[mapped login name],    
		[permission path]   
	FROM     
		#ADGroupMember   
	WHERE     
		[type] = 'group';       
		
	/* Clear table to repopulate for Group Loop */   
	TRUNCATE TABLE #ADGroupMember;       
	
	WHILE EXISTS ( SELECT TOP 1 [account name] FROM #GroupLoop WHERE [IsProcessed] = 0 AND [type] = 'group' )   
	BEGIN    
	
		DECLARE @GroupName [varchar](128);    
		DECLARE @CreateGroup [tinyint] = 0;    
		DECLARE @SQLStmt [varchar](1000);        
		
		SELECT TOP 1      
			@GroupName = [account name]    
		FROM      
			#GroupLoop     
		WHERE      
			[IsProcessed] = 0     
			AND [type] = 'group';        
			
		/* xp_logininfo won't return info if group does not explicitly exist. So if it doesn't then a CREATE/DROP is performed. */    
		SELECT      
			@CreateGroup = COUNT([name])     
		FROM      
			[master].[sys].[syslogins]     
		WHERE      
			[name] = @GroupName;        
			
		IF @CreateGroup = 0    
		BEGIN      
			SET @SQLStmt = 'CREATE LOGIN [' + @GroupName + '] FROM WINDOWS WITH DEFAULT_DATABASE=[master];';     
			EXEC(@SQLStmt);           
			
			INSERT INTO #ADGroupMember ( [account name], [type], [privilege], [mapped login name], [permission path] )     
			EXEC [master]..[xp_logininfo] @acctname = @GroupName, @option = 'members';         
			
			SET @SQLStmt = 'DROP LOGIN [' + @GroupName + '];';     
			EXEC(@SQLStmt);    
		END         
		
		IF @CreateGroup > 0    
		BEGIN      
			INSERT INTO #ADGroupMember ( [account name], [type], [privilege], [mapped login name], [permission path] )     
			EXEC [master]..[xp_logininfo] @acctname = @GroupName, @option = 'members';    
		END        
		
		INSERT INTO #SysLogins ( [sid],[name],[status],[isntgroup],[MemberOfGroup] )    
		SELECT
			msl.[sid],
			a.[account name],
			s.[status],
			s.[isntgroup],
			g.[permission path]     
		FROM
			#ADGroupMember a     
			LEFT OUTER JOIN #SysLogins s       
				ON s.[name] = a.[permission path]     
			LEFT OUTER JOIN #GroupLoop g      
				ON g.[account name] = a.[permission path]     
			left outer join master.sys.syslogins msl      
				on s.[name] = msl.[name]    
		WHERE      
			s.[MemberOfGroup] IS NOT NULL;        
			
		/* If a member is a group than this group is added to #GroupLoop to be checked also */    
		INSERT INTO #GroupLoop ( [account name],[type],[privilege],[mapped login name],[permission path] )    
		SELECT
			[account name],
			[type],
			[privilege],
			[mapped login name],
			[permission path]    
		FROM
			#ADGroupMember    
		WHERE
			[type] = 'group';        
		
		TRUNCATE TABLE #ADGroupMember;        
		
		UPDATE #GroupLoop    
		SET      
			[IsProcessed] = 1    
		WHERE      
			[account name] = @GroupName;   
		
	END       
	
	/* insert into [security_audit] staging table if Principal is a member of at least one ADGroup */   
	insert [security_audit].[Staging_PrincipalToADGroupMappings]([sid],[PrincipalName],[ADGroupName])   
	select
		[sid],
		[name],
		[MemberOfGroup]   
	from 
		#SysLogins   
	where 
		[MemberOfGroup] is not null;
	
	commit;

	/* clean up */   
	drop table if exists #GroupLoop;   
	drop table if exists #SysLogins;   
	drop table if exists #ADGroupMember;   
	drop table if exists #NtGroup;  

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
	drop table if exists #GroupLoop;   
	drop table if exists #SysLogins;   
	drop table if exists #ADGroupMember;   
	drop table if exists #NtGroup;  

end catch

end