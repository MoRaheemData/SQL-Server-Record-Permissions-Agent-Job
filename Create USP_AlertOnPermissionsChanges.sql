use [EnterDBNameHere];
go

create or alter procedure [security_audit].[USP_AlertOnPermissionsChanges] ( @Recipients varchar(1000))
as
begin

/*
	Alert DBA Team On Identified Security Changes
	
	Things that are alerted on:
	- New access granted (includes new members of AD Groups, adding members to db roles )
	- Access revoked (includes dropped principals, dropped members from db roles, dropped members from AD Groups )
	- Orphaned database user
	
	Change log:
	Date:		Author:			Notes:
	20220503	Mo Raheem		Created
	20220513	Mo Raheem		Changed "order by" from msdb.dbo.sysjobhistory.run_date to msdb.dbo.sysjobactivity.stop_execution_date
	20220517	Mo Raheem		Changed @JobLastStopExecutionDate to reference "audit" job
	20220519	Mo Raheem		Added reporting on [security_audit].[RevokedInstancePermissions] & [security_audit].[RevokedDatabasePermissions]
	20220523	Mo Raheem		Added logging to audit table, and reporting on last run time of this Alerting USP
*/

set nocount on;

declare 
	@JobLastStopExecutionDate datetime,
	@OutputMessage varchar(4000), /* Used to print messages to the log */
	@DatabaseName varchar(128),
	@SQLStmt varchar(4000), /* Used for executing dynamic SQL statements */
	@RecordPermissionsAuditID int, /* used for auditing USP execution */
	/* Needed for DBMail */
	@Subject varchar(100) = (select @@SERVERNAME),
	@TableHTML varchar(max),
	@InstanceLevelPermissionsChangesHTML varchar(max),
	@DatabaseLevelPermissionsChangesHTML varchar(max),
	@NewDatabaseRoleMembersHTML varchar(max),
	@NewADGroupMembersHTML varchar(max),
	@AccessRevokedHTML varchar(max),
	@DroppedPrincipalsHTML varchar(max),
	@DroppedMembersFromADGroupHTML varchar(max),
	@DroppedMembersFromDatabaseRolesHTML varchar(max),
	@OrphanedDatabaseUserHTML varchar(max),
	@RevokedInstancePermissionsHTML varchar(max),
	@RevokedDatabasePermissionsHTML varchar(max)
;

/* 
	Select stop execution date & time of last successful run, used later on for reporting on changes 
*/
select 
	@JobLastStopExecutionDate = max([ExecStartDT])
from 
	[security_audit].[RecordPermissionsAudit]
where
	[USPName] = 'USP_AlertOnPermissionsChanges'
	and [SuccessIndicator] = 'Y';

if @JobLastStopExecutionDate is null
begin
	/* Insert dummy record first time USP is run to (1) not report on every securable, and (2) to make the logic work going forward */
	insert [security_audit].[RecordPermissionsAudit] ([USPName],[ExecStartDT],[ExecStopDT],[SuccessIndicator])
	values 
		('USP_AlertOnPermissionsChanges',getdate(),getdate(),'Y');

	return
end

print 'Using @JobLastStopExecutionDate = ' + convert(varchar,@JobLastStopExecutionDate,21);

/* 
	Log to audit table that USP_AlertOnPermissionsChanges has been executed 
*/
insert [security_audit].[RecordPermissionsAudit] ([USPName])
values 
	('USP_AlertOnPermissionsChanges');

select @RecordPermissionsAuditID = SCOPE_IDENTITY(); /* query newly incremented identity value from above insert */

/*
	New access granted
*/
/* Instance */
drop table if exists #InstanceLevelPermissionsChanges;
create table #InstanceLevelPermissionsChanges (
	ServerName varchar(257),
	Scope varchar(128),
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	PermissionType varchar(128),
	PermissionState varchar(5),
	ClassDescription varchar(20),
	EndpointName varchar(128),
	PollDate datetime
);

insert #InstanceLevelPermissionsChanges (ServerName,Scope,PrincipalName,PrincipalType,PermissionType,PermissionState,ClassDescription,EndpointName,PollDate)
select
	ServerName,
	Scope,
	PrincipalName,
	PrincipalType,
	PermissionType,
	PermissionState,
	ClassDescription,
	EndpointName,
	PollDate
from
	[security_audit].[InstanceLevel]
where
	PollDate > @JobLastStopExecutionDate;

/* Database */
drop table if exists #DatabaseLevelPermissionsChanges;
create table #DatabaseLevelPermissionsChanges (
	ServerName varchar(257),
	Scope varchar(128),
	PrincipalName varchar(128),
	ObjectType varchar(128),
	PermissionType varchar(128),
	PermissionState varchar(5),
	SchemaName varchar(128),
	ObjectName varchar(128),
	ColumnName varchar(128),
	PollDate datetime
);

insert #DatabaseLevelPermissionsChanges (ServerName,Scope,PrincipalName,ObjectType,PermissionType,PermissionState,SchemaName,ObjectName,ColumnName,PollDate)
select
	ServerName,
	Scope,
	PrincipalName,
	ObjectType,
	PermissionType,
	PermissionState,
	SchemaName,
	ObjectName,
	ColumnName,
	PollDate
from
	[security_audit].[DatabaseObjectLevel]
where
	PollDate > @JobLastStopExecutionDate;

/* Database roles */
drop table if exists #NewDatabaseRoleMembers;
create table #NewDatabaseRoleMembers (
	[ServerName] [varchar](257) NULL,
	[Scope] [varchar](128) NULL,
	[PrincipalName] [varchar](128) NULL,
	[PrincipalType] [varchar](50) NULL,
	[DatabaseRole] [varchar](128) NULL,
	[PollDate] datetime null
);

insert #NewDatabaseRoleMembers ([ServerName],[Scope],[PrincipalName],[PrincipalType],[DatabaseRole],PollDate)
select 
	[ServerName],
	[Scope],
	[PrincipalName],
	[PrincipalType],
	[DatabaseRole],
	PollDate
from
	[security_audit].[PrincipalToDatabaseRoleMappings]
where
	PollDate > @JobLastStopExecutionDate;

/*	New members of AD Groups */
drop table if exists #NewADGroupMembers;
create table #NewADGroupMembers (
	ServerName varchar(257),
	PrincipalName varchar(128),
	ADGroupName varchar(128),
	PollDate datetime
);

insert #NewADGroupMembers (ServerName,PrincipalName,ADGroupName,PollDate)
select
	@@servername,
	PrincipalName,
	ADGroupName,
	PollDate
from
	[security_audit].[PrincipalToADGroupMappings]
where
	PollDate > @JobLastStopExecutionDate;

/*
	Access revoked
*/
/* Instance */
drop table if exists #AccessRevoked;
create table #AccessRevoked (
	ServerName varchar(257),
	Scope varchar(128),
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	IsDisabled varchar(3),
	PermissionType varchar(128),
	PermissionState varchar(5),
	ClassDescription varchar(20),
	PollDate datetime
);

insert #AccessRevoked (ServerName,Scope,PrincipalName,PrincipalType,IsDisabled,PermissionType,PermissionState,ClassDescription,PollDate)
select
	ServerName,
	Scope,
	PrincipalName,
	PrincipalType,
	IsDisabled,
	PermissionType,
	PermissionState,
	ClassDescription,
	PollDate
from
	[security_audit].[InstanceLevel]
where 
	PollDate > @JobLastStopExecutionDate
	and ((PermissionType = 'CONNECT SQL' and PermissionState = 'DENY')
		or (IsDisabled = 'Yes'));

/* Dropped principals */
drop table if exists #DroppedPrincipals;
create table #DroppedPrincipals (
	ServerName varchar(257),
	Scope varchar(128),
	PrincipalName varchar(128),
	PrincipalType varchar(128),
	PollDate datetime
);

insert #DroppedPrincipals (ServerName,Scope,PrincipalName,PrincipalType,PollDate)
select
	ServerName,
	Scope,
	PrincipalName,
	PrincipalType,
	PollDate
from
	[security_audit].[DroppedPrincipals]
where
	PollDate > @JobLastStopExecutionDate;

/* Dropped Members From AD Groups */
drop table if exists #DroppedMembersFromADGroup
create table #DroppedMembersFromADGroup (
	[ServerName] varchar(257) null,
	[PrincipalName] [varchar](128) NULL,
	[ADGroupName] [varchar](128) NULL,
	[PollDate] [datetime] NULL
);

insert #DroppedMembersFromADGroup ([ServerName],[PrincipalName],[ADGroupName],[PollDate])
select
	@@SERVERNAME,
	[PrincipalName],
	[ADGroupName],
	[PollDate]
from
	[security_audit].[DroppedMembersFromADGroups]
where
	PollDate > @JobLastStopExecutionDate;

/* Dropped Members From Database Roles */
drop table if exists #DroppedMembersFromDatabaseRoles;
create table #DroppedMembersFromDatabaseRoles (
	[ServerName] [varchar](257) NULL,
	[Scope] [varchar](128) NULL,
	[PrincipalName] [varchar](128) NULL,
	[PrincipalType] [varchar](50) NULL,
	[DatabaseRole] [varchar](128) NULL,
	[PollDate] [datetime] NULL
);

insert #DroppedMembersFromDatabaseRoles ([ServerName],[Scope],[PrincipalName],[PrincipalType],[DatabaseRole],[PollDate])
select 
	[ServerName],
	[Scope],
	[PrincipalName],
	[PrincipalType],
	[DatabaseRole],
	[PollDate]
from
	[security_audit].[DroppedMembersFromDatabaseRoles]
where
	PollDate > @JobLastStopExecutionDate;

/* Revoked Instance Permissions */
drop table if exists #RevokedInstancePermissions;
create table #RevokedInstancePermissions (
	[ServerName] [varchar](257) NULL,
	[Scope] [varchar](128) NULL,
	[PrincipalName] [varchar](128) NULL,
	[PrincipalType] [varchar](50) NULL,
	[IsDisabled] [varchar](3) NULL,
	[PermissionType] [varchar](128) NULL,
	[PermissionState] [varchar](25) NULL,
	[ClassDescription] [varchar](20) NULL,
	[PollDate] [datetime] NULL
);

insert #RevokedInstancePermissions ([ServerName],[Scope],[PrincipalName],[PrincipalType],[IsDisabled],[PermissionType],[PermissionState],[ClassDescription],[PollDate])
select
	[ServerName]
	,[Scope]
	,[PrincipalName]
	,[PrincipalType]
	,[IsDisabled]
	,[PermissionType]
	,[PermissionState]
	,[ClassDescription]
	,[PollDate]
from
	[security_audit].[RevokedInstancePermissions]
where
	PollDate > @JobLastStopExecutionDate;

/* Revoked Database Permissions */
drop table if exists #RevokedDatabasePermissions;
create table #RevokedDatabasePermissions (
	[ServerName] [varchar](257) NULL,
	[Scope] [varchar](128) NULL,
	[PrincipalName] [varchar](128) NULL,
	[ObjectType] [varchar](128) NULL,
	[PermissionType] [varchar](128) NULL,
	[PermissionState] [varchar](25) NULL,
	[SchemaName] [varchar](128) NULL,
	[ObjectName] [varchar](128) NULL,
	[ColumnName] [varchar](128) NULL,
	[PollDate] [datetime] NULL
);

insert #RevokedDatabasePermissions ([ServerName],[Scope],[PrincipalName],[ObjectType],[PermissionType],[PermissionState],[SchemaName],[ObjectName],[ColumnName],[PollDate])
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
	[security_audit].[RevokedDatabasePermissions]
where
	PollDate > @JobLastStopExecutionDate;


/*
	Orphaned database user
*/
drop table if exists #OrphanedDatabaseUser;
create table #OrphanedDatabaseUser (
	ServerName varchar(257),
	Scope varchar(128),
	PrincipalName varchar(128),
	PollDate datetime
);

/* stores db role info to filter on later */
drop table if exists #DatabaseRoles;
create table #DatabaseRoles (
	[sid] varbinary(85)
);

drop table if exists #ValidDatabase;
create table #ValidDatabase (
	DatabaseName varchar(128),
	IsProcessed bit default 0
);

insert #ValidDatabase (DatabaseName)
select
	[name]
from
	master.sys.databases
where
	state_desc = 'ONLINE'
	and user_access_desc = 'MULTI_USER';

while exists (select 1 from #ValidDatabase where IsProcessed = 0)
begin
	select top 1 
		@DatabaseName = DatabaseName
	from 
		#ValidDatabase 
	where 
		IsProcessed = 0;

	set @SQLStmt = '
	insert #DatabaseRoles ([sid])
	select 
		[sid]
	from 
		[' + @DatabaseName + '].sys.database_principals
	where
		type_desc = ''DATABASE_ROLE''
	;';
	exec(@SQLStmt);

	update #ValidDatabase
	set 
		IsProcessed = 1
	where
		DatabaseName = @DatabaseName;
end

insert #OrphanedDatabaseUser (ServerName,Scope,PrincipalName,PollDate)
select
	ServerName,
	Scope,
	PrincipalName,
	PollDate
from 
	[security_audit].[DatabaseObjectLevel]
where
	[sid] not in (
		select
			[sid]
		from
			[security_audit].[InstanceLevel]
		)
	/* exclude database roles */
	and [sid] not in (
		select
			[sid]
		from
			#DatabaseRoles
		)
	and PollDate > @JobLastStopExecutionDate;


/*
	Email Logic	
*/ 

if ( select count(ServerName) from #InstanceLevelPermissionsChanges ) > 0 
begin 
	SET @InstanceLevelPermissionsChangesHTML = 
		N'<H1>New Instance Level Permissions</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Principal Type</th>' + 
		N'<th>Permission Type</th>' + 
		N'<th>Permission State</th>' + 
		N'<th>Class Description</th>' + 
		N'<th>Endpoint Name</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = PrincipalType, '   ', 
			td = PermissionType, '   ', 
			td = PermissionState, '   ', 
			td = ClassDescription, '   ', 
			td = EndpointName, '   ', 
			td = PollDate
		from 
			#InstanceLevelPermissionsChanges
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #DatabaseLevelPermissionsChanges ) > 0 
begin 
	SET @DatabaseLevelPermissionsChangesHTML = 
		N'<H1>New Database Level Permissions</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Object Type</th>' + 
		N'<th>Permission Type</th>' + 
		N'<th>Permission State</th>' + 
		N'<th>Schema Name</th>' + 
		N'<th>Object Name</th>' + 
		N'<th>Column Name</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = ObjectType, '   ', 
			td = PermissionType, '   ', 
			td = PermissionState, '   ', 
			td = SchemaName, '   ', 
			td = ObjectName, '   ', 
			td = ColumnName, '   ', 
			td = PollDate
		from 
			#DatabaseLevelPermissionsChanges
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #NewDatabaseRoleMembers ) > 0 
begin 
	SET @NewDatabaseRoleMembersHTML = 
		N'<H1>New Database Role Membership</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Principal Type</th>' + 
		N'<th>Database Role</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = [PrincipalType], '   ', 
			td = [DatabaseRole], '   ', 
			td = PollDate
		from 
			#NewDatabaseRoleMembers
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #NewADGroupMembers ) > 0 
begin 
	SET @NewADGroupMembersHTML = 
		N'<H1>New AD Group Membership</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>AD Group Name</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = PrincipalName, '   ', 
			td = ADGroupName, '   ', 
			td = PollDate
		from 
			#NewADGroupMembers
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #AccessRevoked ) > 0 
begin 
	SET @AccessRevokedHTML = 
		N'<H1>Connection Denied</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Principal Type</th>' + 
		N'<th>Is Disabled</th>' + 
		N'<th>Permission Type</th>' + 
		N'<th>Permission State</th>' + 
		N'<th>Class Description</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = PrincipalType, '   ', 
			td = IsDisabled, '   ', 
			td = PermissionType, '   ', 
			td = PermissionState, '   ', 
			td = ClassDescription, '   ', 
			td = PollDate
		from 
			#AccessRevoked
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #DroppedPrincipals ) > 0 
begin 
	SET @DroppedPrincipalsHTML = 
		N'<H1>Dropped Principals</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Principal Type</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = PrincipalType, '   ', 
			td = PollDate
		from 
			#DroppedPrincipals
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #DroppedMembersFromADGroup ) > 0 
begin 
	SET @DroppedMembersFromADGroupHTML = 
		N'<H1>Dropped Members From AD Group</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>AD Group Name</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = [PrincipalName], '   ', 
			td = [ADGroupName], '   ', 
			td = PollDate
		from 
			#DroppedMembersFromADGroup
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #DroppedMembersFromDatabaseRoles ) > 0 
begin 
	SET @DroppedMembersFromDatabaseRolesHTML = 
		N'<H1>Dropped Members From Database Roles</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Principal Type</th>' + 
		N'<th>Database Role</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = PrincipalType, '   ', 
			td = [DatabaseRole], '   ', 
			td = PollDate
		from 
			#DroppedMembersFromDatabaseRoles
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #OrphanedDatabaseUser ) > 0 
begin 
	SET @OrphanedDatabaseUserHTML = 
		N'<H1>Orphaned Database Users</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = ServerName, '   ', 
			td = Scope, '   ', 
			td = PrincipalName, '   ', 
			td = PollDate
		from 
			#OrphanedDatabaseUser
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #RevokedInstancePermissions ) > 0 
begin 
	SET @RevokedInstancePermissionsHTML = 
		N'<H1>Revoked Instance Permissions</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Principal Type</th>' + 
		N'<th>Is Disabled</th>' + 
		N'<th>Permission Type</th>' + 
		N'<th>Permission State</th>' + 
		N'<th>Class Description</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = [ServerName], '   ', 
			td = [Scope], '   ', 
			td = [PrincipalName], '   ', 
			td = [PrincipalType], '   ', 
			td = [IsDisabled], '   ', 
			td = [PermissionType], '   ', 
			td = [PermissionState], '   ', 
			td = [ClassDescription], '   ', 
			td = [PollDate]
		from 
			#RevokedInstancePermissions
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

if ( select count(ServerName) from #RevokedDatabasePermissions ) > 0 
begin 
	SET @RevokedDatabasePermissionsHTML = 
		N'<H1>Revoked Database Permissions</H1>' + 
		N'<table border="1">' + 
		N'<tr><th>Server Name</th>' + 
		N'<th>Scope</th>' + 
		N'<th>Principal Name</th>' + 
		N'<th>Object Type</th>' + 
		N'<th>Permission Type</th>' + 
		N'<th>Permission State</th>' + 
		N'<th>Schema Name</th>' + 
		N'<th>Object Name</th>' + 
		N'<th>Column Name</th>' + 
		N'<th>Poll Date</th></tr>' + 
	CAST ( ( 
		select 
			td = [ServerName], '   ', 
			td = [Scope], '   ', 
			td = [PrincipalName], '   ', 
			td = [ObjectType], '   ', 
			td = [PermissionType], '   ', 
			td = [PermissionState], '   ', 
			td = [SchemaName], '   ', 
			td = [ObjectName], '   ', 
			td = [ColumnName], '   ', 
			td = [PollDate]
		from 
			#RevokedDatabasePermissions
	FOR XML PATH('tr'), TYPE 
	   ) AS NVARCHAR(MAX) ) + 
	   N'</table>' 
end

/* Format email */
set @TableHTML = '';

if @InstanceLevelPermissionsChangesHTML is not null
begin
	set @TableHTML += @InstanceLevelPermissionsChangesHTML 
end

if @DatabaseLevelPermissionsChangesHTML is not null
begin
	set @TableHTML += @DatabaseLevelPermissionsChangesHTML 
end

if @NewDatabaseRoleMembersHTML is not null
begin
	set @TableHTML += @NewDatabaseRoleMembersHTML 
end

if @NewADGroupMembersHTML is not null
begin
	set @TableHTML += @NewADGroupMembersHTML 
end

if @AccessRevokedHTML is not null
begin
	set @TableHTML += @AccessRevokedHTML 
end

if @DroppedPrincipalsHTML is not null
begin
	set @TableHTML += @DroppedPrincipalsHTML 
end

if @DroppedMembersFromADGroupHTML is not null
begin
	set @TableHTML += @DroppedMembersFromADGroupHTML 
end

if @DroppedMembersFromDatabaseRolesHTML is not null
begin
	set @TableHTML += @DroppedMembersFromDatabaseRolesHTML 
end

if @OrphanedDatabaseUserHTML is not null
begin
	set @TableHTML += @OrphanedDatabaseUserHTML 
end

/* send email if there are any result sets */
if len(@TableHTML) > 0 
begin	
	set @Subject +=  + ' - Permissions Changes Alert'

	exec [msdb].[dbo].[sp_send_dbmail] 
		@recipients = @Recipients, 
		@subject = @Subject, 
		@body = @TableHTML, 
		@body_format = 'HTML' 
end

/*
	Mark USP as having completed successfully in audit table
*/
update [security_audit].[RecordPermissionsAudit]
	set
		[ExecStopDT] = getdate(),
		[SuccessIndicator] = 'Y'
	where
		[RecordPermissionsAuditID] = @RecordPermissionsAuditID;

/* clean up */
drop table if exists #AccessRevoked;
drop table if exists #DatabaseLevelPermissionsChanges;
drop table if exists #DatabaseRoles;
drop table if exists #DroppedPrincipals;
drop table if exists #InstanceLevelPermissionsChanges;
drop table if exists #NewADGroupMembers;
drop table if exists #ValidDatabase;
drop table if exists #DroppedMembersFromADGroup;
drop table if exists #DroppedMembersFromDatabaseRoles
drop table if exists #NewDatabaseRoleMembers;
drop table if exists #OrphanedDatabaseUser
drop table if exists #RevokedDatabasePermissions;
drop table if exists #RevokedInstancePermissions;

end