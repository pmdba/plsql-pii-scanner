/* Create table to hold search criteria */

create table pii_sensitive_types
(
  sensitive_type_name  varchar2(30 char)        not null,
  col_name_pattern     varchar2(256 char)       not null,
  col_comment_pattern  varchar2(256 char)       not null,
  sensitive_category   varchar2(30 char),
  enforced             varchar2(1 char)         default 'Y'
);

comment on table pii_sensitive_types is 'This table contains sensitive types and their related regular expressions and categories';
comment on column pii_sensitive_types.sensitive_type_name is 'Name of the Sensitive Type';
comment on column pii_sensitive_types.col_name_pattern is 'REGEX used to search Column Names';
comment on column pii_sensitive_types.col_comment_pattern is 'REGEX used to search Column Comments';
comment on column pii_sensitive_types.sensitive_category is 'Sensitive Category to which the sensitive type belongs to';

create unique index pii_sensitive_types_pk on pii_sensitive_types
(sensitive_type_name);

alter table pii_sensitive_types add (
  constraint pii_sensitive_types_pk
  primary key
  (sensitive_type_name)
  using index pii_sensitive_types_pk
  enable validate);
