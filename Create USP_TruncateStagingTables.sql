use [DbaToolbox];
go

create or alter procedure [security_audit].[USP_TruncateStagingTables] 
as 
begin

set nocount on;

declare 
	@SQLStmt varchar(4000),
	@OutputMessage as varchar(4000)
;
	
/* gather list of Staging tables */
drop table if exists #TruncateStagingTables;
create table #TruncateStagingTables (
	TruncateCommand varchar(4000),
	IsProcessed bit default 0
);

insert #TruncateStagingTables (TruncateCommand)
select 
	'truncate table [' + s.name + '].[' + t.name + '];'
from
	[DbaToolbox].sys.schemas s
	inner join [DbaToolbox].sys.tables t
		on t.schema_id = s.schema_id
where
	s.name = 'security_audit'
	and t.name like 'Staging%';

/* loop through Staging tables and truncate */
while exists (select 1 from #TruncateStagingTables where IsProcessed = 0)
begin
	select top 1	
		@SQLStmt = TruncateCommand
	from
		#TruncateStagingTables 
	where 
		IsProcessed = 0;

	set @OutputMessage = convert(varchar, getdate(), 21) + ': Running statement: ' + @SQLStmt;
	raiserror('%s',0,1,@OutputMessage) with nowait;
	
	exec(@SQLStmt);

	update #TruncateStagingTables
	set		
		IsProcessed = 1
	where
		TruncateCommand = @SQLStmt;
end

/* clean up */
drop table if exists #TruncateStagingTables;

end