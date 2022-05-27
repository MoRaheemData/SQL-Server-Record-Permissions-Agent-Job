USE [DbaToolbox]
GO
/****** Object:  StoredProcedure [security_audit].[USP_GetUsersPermissions]    Script Date: 4/15/2022 1:14:16 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE OR ALTER PROCEDURE [security_audit].[USP_GetUsersPermissions]
	@PrincipalName varchar(128)
as
begin

declare @sid varbinary(85) = (select [sid] from master.sys.syslogins where [name] = @PrincipalName);

/* Get Instance Level Permissions */
select 
	[ServerName]
	,[Scope]
	,[sid]
	,[PrincipalName]
	,[PrincipalType]
	,[IsDisabled]
	,[PermissionType]
	,[PermissionState]
	,[ClassDescription]
	,[EndpointName]
	,[PollDate]
from 
	[security_audit].[InstanceLevel]
where 
	PrincipalName = @PrincipalName
	/* grab the principal's AD Groups which have access to the instance */
	or PrincipalName in (
		select 
			ad.[ADGroupName]
		from 
			[security_audit].[PrincipalToADGroupMappings] ad
		where
			PrincipalName = @PrincipalName);

/* Get Database Role Mappings */
select 
	@@servername as ServerName,
	[Scope],
	[PrincipalName],
	[PrincipalType],
	[DatabaseRole],
	[PollDate]
from 
	[security_audit].[PrincipalToDatabaseRoleMappings]
where 
	PrincipalName = @PrincipalName
/* grab the principal's AD Groups which have access to the instance */
or PrincipalName in (
	select 
		ad.[ADGroupName]
	from 
		[security_audit].[PrincipalToADGroupMappings] ad
	where
		PrincipalName = @PrincipalName);

/* Get User's Database Role Permissions */
;WITH DBRole_CTE ([Scope], [PrincipalName], [DatabaseRole])  
AS (
	select 
		[Scope],
		[PrincipalName],
		[DatabaseRole]
	from 
		[security_audit].[PrincipalToDatabaseRoleMappings]
	where 
		PrincipalName = @PrincipalName
	/* grab the principal's AD Groups which have access to the instance */
	or PrincipalName in (
		select 
			ad.[ADGroupName]
		from 
			[security_audit].[PrincipalToADGroupMappings] ad
		where
			PrincipalName = @PrincipalName )
)  
select 
	do.[ServerName]
	,do.[Scope]
	,do.[PrincipalName]
	,do.[ObjectType]
	,do.[PermissionType]
	,do.[PermissionState]
	,do.[SchemaName]
	,do.[ObjectName]
	,do.[ColumnName]
	,do.[PollDate]
from 
	[security_audit].[DatabaseObjectLevel] do
	join DBRole_CTE c
		on c.Scope = do.Scope
		and c.DatabaseRole = do.PrincipalName;

/* Get User's Database Object Permissions */
select 
	[ServerName]
	,[Scope]
	,[PrincipalName]
	,[ObjectType]
	,[PermissionType]
	,[PermissionState]
	,[SchemaName]
	,[ObjectName]
	,[ColumnName]
	,[PollDate]
from 
	[security_audit].[DatabaseObjectLevel]
where
	PrincipalName = @PrincipalName
	/* grab the principal's AD Groups which have access to the instance */
	or PrincipalName in (
		select 
			ad.[ADGroupName]
		from 
			[security_audit].[PrincipalToADGroupMappings] ad
		where
			PrincipalName = @PrincipalName )
	or [sid] = @sid;

end