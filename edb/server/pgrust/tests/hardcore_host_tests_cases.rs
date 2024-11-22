mod test_util;

test_case!(host_1, "postgres://host:1", output = {"host": "host", "port": "1"}, no_env = no_env);

test_case!(
    host_2,
    "postgres://host:1?host=host2",
    output = {"host": "host2", "port": "1"},
    no_env = no_env
);

test_case!(
    host_3,
    "postgres://host:1,host2:",
    output = {"port": "1,", "host": "host,host2"},
    no_env = no_env
);

test_case!(
    host_4,
    "postgres://host:1,host2:,host3,host4:4",
    output = {"host": "host,host2,host3,host4", "port": "1,,,4"},
    no_env = no_env
);

test_case!(
    host_5,
    "postgres://host:1?port=2,3",
    output = {"port": "2,3", "host": "host"},
    no_env = no_env
);

test_case!(host_6, "postgres://host,host2:2", output = {"host": "host,host2", "port": ",2"}, no_env = no_env);

test_case!(
    host_ipv6,
    "postgres://?host=::1",
    output = {"host": "::1"},
    no_env = no_env
);

test_case!(port_only_1, "postgres://:1", output = {"port": "1"}, no_env = no_env);

test_case!(port_only_2, "postgres://:1,:2", output = {"host": ",", "port": "1,2"}, no_env = no_env);

test_case!(port_host_mix, "postgres://:1,host2:2,:3", output = {"port": "1,2,3", "host": ",host2,"}, no_env = no_env);

test_case!(db_override_1, "postgres:///db?dbname=db2", output={
    "dbname": "db2",
}, no_env=no_env);

test_case!(db_override_2, "postgres:///?dbname=db2", output={
    "dbname": "db2",
}, no_env=no_env);

test_case!(db_override_3, "postgres://?dbname=db3", output={
    "dbname": "db3",
}, no_env=no_env);

test_case!(empty_host, "postgres://user@/?host=,", output = {
    "host": "/var/run/postgresql,/var/run/postgresql",
    "user": "user",
    "dbname": "user",
    "port": "5432,5432",
});

test_case!(empty_param, "postgres://user@old_host:1234?host=&port=", output={
    "port": "5432",
    "host": "/var/run/postgresql",
    "user": "user",
    "dbname": "user",
});

test_case!(
    hosts_in_host_param,
    "postgres://user@/dbname?host=[::1]",
    error = "Invalid DSN.*",
    expect_libpq_mismatch = "libpq allows for these invalid hostnames"
);

test_case!(
    non_ipv6_in_brackets,
    "postgres://user@[localhost]/dbname",
    output={
        "user": "user",
        "host": "localhost",
        "port": "5432",
        "dbname": "dbname",
    }
);

test_case!(
    path_in_host,
    "postgres://user@%2ffoo/dbname",
    output={
        "user": "user",
        "host": "/foo",
        "port": "5432",
        "dbname": "dbname",
    }
);

test_case!(
    path_in_host_2,
    "postgres://user@[/foo]/dbname",
    output={
        "user": "user",
        "host": "/foo",
        "port": "5432",
        "dbname": "dbname",
    }
);

test_case!(
    path_in_host_3,
    "postgres://user@[/foo],[/bar]/dbname",
    output={
        "user": "user",
        "host": "/foo,/bar",
        "port": "5432,5432",
        "dbname": "dbname",
    }
);
