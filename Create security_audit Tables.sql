use [EnterDBNameHere];
go

/*
	Clean up statements (run output) - 

	select 'drop table if exists [' + s.name + '].[' + t.name + '];'
	from 
		DbaToolbox.sys.schemas s
		inner join DbaToolbox.sys.tables t
			on t.schema_id = s.schema_id
	where
		s.name = 'security_audit';

	use [DbaToolbox];
	go
	
	drop schema [security_audit];
	go
*/

/*
	Create schema
*/
create schema [security_audit];
go

/*
	Create tables
*/
create table [security_audit].[RecordPermissionsAudit](
	[RecordPermissionsAuditID] [int] IDENTITY(1,1) NOT NULL,
	[ParentAuditID] int default -1 not null,
	[USPName] [varchar](128) not null,
	[ExecStartDT] [datetime] default getdate() NOT NULL,
	[ExecStopDT] [datetime] NULL,
	[RunBy] [varchar](24) NOT NULL default suser_sname(),
	[SuccessIndicator] [char](1) default 'N' NOT NULL,
	CONSTRAINT [PK_RecordPermissionsAudit_RecordPermissionsAuditID] PRIMARY KEY CLUSTERED ([RecordPermissionsAuditID] ASC)
);

create table [security_audit].[InstanceLevel] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	IsDisabled varchar(3),
	PermissionType varchar(128),
	PermissionState varchar(5),
	ClassDescription varchar(20),
	EndpointName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[PrincipalToADGroupMappings] (
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	ADGroupName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[PrincipalToDatabaseRoleMappings] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	DatabaseRole varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[DatabaseObjectLevel] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	ObjectType varchar(128),
	PermissionType varchar(128),
	PermissionState varchar(5),
	SchemaName varchar(128),
	ObjectName varchar(128),
	ColumnName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[DroppedPrincipals] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[DroppedMembersFromADGroups] (
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	ADGroupName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[DroppedMembersFromDatabaseRoles] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	DatabaseRole varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[RevokedDatabasePermissions] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	ObjectType varchar(128),
	PermissionType varchar(128),
	PermissionState varchar(5),
	SchemaName varchar(128),
	ObjectName varchar(128),
	ColumnName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[RevokedInstancePermissions] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	IsDisabled varchar(3),
	PermissionType varchar(128),
	PermissionState varchar(5),
	ClassDescription varchar(20),
	EndpointName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[Staging_InstanceLevel] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	IsDisabled varchar(3),
	PermissionType varchar(128),
	PermissionState varchar(5),
	ClassDescription varchar(20),
	EndpointName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[Staging_PrincipalToADGroupMappings] (
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	ADGroupName varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[Staging_PrincipalToDatabaseRoleMappings] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	PrincipalType varchar(50),
	DatabaseRole varchar(128),
	PollDate datetime default getdate()
);

create table [security_audit].[Staging_DatabaseObjectLevel] (
	ServerName varchar(257),
	Scope varchar(128),
	[sid] varbinary(85) null,
	PrincipalName varchar(128),
	ObjectType varchar(128),
	PermissionType varchar(128),
	PermissionState varchar(5),
	SchemaName varchar(128),
	ObjectName varchar(128),
	ColumnName varchar(128),
	PollDate datetime default getdate()
);