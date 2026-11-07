# prueba
prueba de la base 
-- ADISGEA - Auditoria práctica segura (solo lectura)
-- Compatible con MySQL 8.0.x. No inserta, actualiza ni elimina datos.
-- Ejecutar en una COPIA de pruebas con una cuenta DBA de auditoría.
-- No ejecutar pruebas destructivas en producción.

SELECT 'VERSION' AS test, VERSION() AS result, @@version_comment AS detail;
SELECT 'SECURE_TRANSPORT' AS test, @@GLOBAL.require_secure_transport AS result;
SELECT 'LOCAL_INFILE' AS test, @@GLOBAL.local_infile AS result;
SELECT 'EVENT_SCHEDULER' AS test, @@GLOBAL.event_scheduler AS result;
SELECT 'SQL_MODE' AS test, @@SESSION.sql_mode AS result;
SELECT 'TIME_ZONE' AS test, @@SESSION.time_zone AS result;

-- Cuentas y estado de bloqueo; no muestra hashes ni secretos.
SELECT user, host, account_locked, password_expired
FROM mysql.user
WHERE user LIKE 'adisgea_%'
ORDER BY user, host;

-- Privilegios globales/esquema/tabla concedidos a cuentas ADISGEA.
SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.SCHEMA_PRIVILEGES
WHERE TABLE_SCHEMA='adisgea' AND GRANTEE LIKE '%adisgea_%'
ORDER BY GRANTEE, PRIVILEGE_TYPE;

SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.TABLE_PRIVILEGES
WHERE TABLE_SCHEMA='adisgea' AND GRANTEE LIKE '%adisgea_%'
ORDER BY GRANTEE, TABLE_NAME, PRIVILEGE_TYPE;

-- Roles existentes y asignaciones.
SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST, WITH_ADMIN_OPTION
FROM mysql.role_edges
WHERE TO_USER LIKE 'adisgea_%' OR FROM_USER LIKE 'adisgea_%'
ORDER BY TO_USER, FROM_USER;

-- Objetos y sus definers/security type.
SELECT ROUTINE_TYPE, ROUTINE_NAME, DEFINER, SECURITY_TYPE, SQL_DATA_ACCESS
FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA='adisgea'
ORDER BY ROUTINE_TYPE, ROUTINE_NAME;

SELECT TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION, DEFINER
FROM information_schema.TRIGGERS
WHERE TRIGGER_SCHEMA='adisgea'
ORDER BY EVENT_OBJECT_TABLE, TRIGGER_NAME;

SELECT TABLE_NAME, DEFINER, SECURITY_TYPE, CHECK_OPTION, IS_UPDATABLE
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA='adisgea'
ORDER BY TABLE_NAME;

SELECT EVENT_NAME, DEFINER, STATUS, EVENT_TYPE, EXECUTE_AT, INTERVAL_VALUE, INTERVAL_FIELD
FROM information_schema.EVENTS
WHERE EVENT_SCHEMA='adisgea';

-- Busca columnas sensibles sin índices aparentes por nombre; revisar resultados manualmente.
SELECT c.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE
FROM information_schema.COLUMNS c
LEFT JOIN information_schema.STATISTICS s
  ON s.TABLE_SCHEMA=c.TABLE_SCHEMA
 AND s.TABLE_NAME=c.TABLE_NAME
 AND s.COLUMN_NAME=c.COLUMN_NAME
WHERE c.TABLE_SCHEMA='adisgea'
  AND c.COLUMN_NAME IN ('tenant_id','user_id','email','token_hash','identifier_hmac','expires_at')
  AND s.COLUMN_NAME IS NULL
ORDER BY c.TABLE_NAME, c.COLUMN_NAME;

-- Revisión de tablas que no usan InnoDB.
SELECT TABLE_NAME, ENGINE
FROM information_schema.TABLES
WHERE TABLE_SCHEMA='adisgea' AND TABLE_TYPE='BASE TABLE'
  AND ENGINE <> 'InnoDB';

-- Conteo de objetos para comparar con el manifiesto esperado.
SELECT 'TABLES' AS object_type, COUNT(*) AS object_count
FROM information_schema.TABLES
WHERE TABLE_SCHEMA='adisgea' AND TABLE_TYPE='BASE TABLE'
UNION ALL
SELECT 'VIEWS', COUNT(*)
FROM information_schema.VIEWS WHERE TABLE_SCHEMA='adisgea'
UNION ALL
SELECT 'TRIGGERS', COUNT(*)
FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='adisgea'
UNION ALL
SELECT 'ROUTINES', COUNT(*)
FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='adisgea'
UNION ALL
SELECT 'EVENTS', COUNT(*)
FROM information_schema.EVENTS WHERE EVENT_SCHEMA='adisgea';

-- IMPORTANTE:
-- 1) Ejecutar SHOW GRANTS FOR 'adisgea_definer'@'%';
-- 2) Ejecutar SHOW GRANTS FOR 'adisgea_app'@'%';
-- 3) Ejecutar SHOW GRANTS FOR 'adisgea_logger'@'%';
-- 4) Ejecutar SHOW GRANTS FOR 'adisgea_migrator'@'%';
-- Compartir resultados ocultando nombres de host/IP internos si corresponde.
--
-- Pruebas de inyección SQL:
-- No se ejecutan desde este archivo porque requieren una API/backend.
-- Cuando exista backend, probar entradas como:
--   ' OR '1'='1
--   ' OR 1=1 -- 
--   '; SELECT SLEEP(3); --
-- Solo en endpoints de laboratorio, con datos ficticios y consultas parametrizadas.
-- Un texto de prueba no debe alterar el resultado, provocar demoras ni revelar filas.
