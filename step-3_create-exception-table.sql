/* Create table to hold search exceptions */

create table pii_excluded_cols
(
  owner       varchar2(30 char)                 not null,
  table_name  varchar2(30 char)                 not null,
  column_name varchar2(30 char)                 not null,
  excluded_by varchar2(50 char) default user    not null,
  excluded_on date              default sysdate not null,
  comments    varchar2(4000 char)
);
