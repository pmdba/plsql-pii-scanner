/* Create procedure to conduct scan */

create or replace procedure scan_schema 
    (p_schema in varchar2 default '%', 
     p_mode in varchar2 default 'view', 
     p_pii_category in varchar2 default '%')
as
    -- declare local variables
    l_schema varchar2(30);
    l_mode varchar2(10);
    l_sql varchar2(1000);

    l_pii_search pii_sensitive_types%rowtype;
    l_col_info dba_col_comments%rowtype;

    -- cursor pii_search returns all search criteria
    cursor pii_search 
        (c_pii_category in varchar2)
    is
    select sensitive_type_name,
           col_name_pattern,
           col_comment_pattern,
           sensitive_category,
           enforced
      from pii_sensitive_types
     where lower(sensitive_category) like lower(c_pii_category)
       and lower(enforced)='y'
     order by sensitive_category, sensitive_type_name;

    -- cursor pii_columns returns all columns with potential PII data
    cursor pii_columns 
        (c_schema in varchar2, 
         c_col_name_pattern in varchar2, 
         c_col_comment_pattern in varchar2)
    is
    select c.owner,
           c.table_name,
           c.column_name,
           c.comments 
      from dba_col_comments c
      join dba_objects o on (o.object_type='TABLE' and o.owner = c.owner and o.object_name = c.table_name)
     where c.owner=l_schema 
       and ( regexp_like(c.column_name,c_col_name_pattern) or regexp_like(c.comments,c_col_comment_pattern)) 
       and c.table_name||'.'||c.column_name not in 
           (select e.table_name||'.'||e.column_name 
              from dba_encrypted_columns e 
             where e.owner=c_schema
             union
            select x.table_name||'.'||x.column_name
              from pii_excluded_cols x
             where x.owner=c_schema)
             order by c.owner, c.table_name, c.column_name;

begin
    -- Make user-supplied inputs case-insensitive
    l_mode   := lower(p_mode);
    l_schema := upper(p_schema);

    -- Enable script output
    dbms_output.enable;

    -- Get the list of search criteria for the requested PII type
    open pii_search (p_pii_category);

    -- For each criteria, search the data dictionary for matches
    loop
        fetch pii_search into l_pii_search;
        exit when pii_search%notfound;

        -- Print the current search criteria type
        dbms_output.put_line(l_pii_search.sensitive_category||'::'||l_pii_search.sensitive_type_name||':');

        begin
            -- Get the list of matching columns for the current search criteria
            open pii_columns (l_schema, l_pii_search.col_name_pattern, l_pii_search.col_comment_pattern);

            loop
                fetch pii_columns into l_col_info;
                exit when pii_columns%notfound;

                -- For each matching column build a SQL statement to encrypt the data using TDE.
                -- The DDL statements uses the "no salt" option by default in the event that the 
                -- affected column is included in an existing index
                l_sql := 'alter table '||
                         l_col_info.owner||'.'||l_col_info.table_name||
                         ' modify('||l_col_info.column_name||
                         ' encrypt using ''AES256'' no salt)';

                -- Print the generated SQL statement
                dbms_output.put_line(' '||l_sql);

                -- If the user has specified the "encrypt" option, execute the SQL statement
                if l_mode = 'encrypt' then
                    execute immediate l_sql;
                end if;
            end loop;

            close pii_columns;
        end;
    end loop;

    close pii_search;
end scan_schema;
