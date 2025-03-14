<?php

/**
 * Database core functions if no supported database is configured in PHP
 *
 * @author Stephen Billard (sbillard)
 *
 * @package core
 */
// force UTF-8 Ø

define('DATABASE_SOFTWARE', 'NULL_db');
Define('DATABASE_MIN_VERSION', '0.0.0');
Define('DATABASE_DESIRED_VERSION', '0.0.0');

/**
 * Connect to the database server and select the database.
 * @param array $config the db configuration parameters
 * @param bool $errorstop set to false to omit error messages
 * @return true if successful connection
 */
function db_connect($config, $errorstop = E_USER_WARNING) {
	global $_DB_connection, $_DB_details;
	$_DB_details = unserialize(DB_NOT_CONNECTED);
	$_DB_connection = NULL;
	return false;
}

/**
 * The main query function. Runs the SQL on the connection and handles errors.
 * @param string $sql sql code
 * @param bool $errorstop set to false to supress the error message
 * @return results of the sql statements
 * @since 0.6
 */
function db_query($sql, $errorstop = true) {
	return false;
}

/**
 * Runs a SQL query and returns an associative array of the first row.
 * Doesn't handle multiple rows, so this should only be used for unique entries.
 * @param string $sql sql code
 * @param bool $errorstop set to false to supress the error message
 * @return results of the sql statements
 * @since 0.6
 */
function query_single_row($sql, $errorstop = true) {
	return false;
}

/**
 * Runs a SQL query and returns an array of associative arrays of every row returned.
 * @param string $sql sql code
 * @param bool $errorstop set to false to supress the error message
 * @param string $key optional array index key
 * @return results of the sql statements
 * @since 0.6
 */
function query_full_array($sql, $errorstop = true, $key = NULL) {
	return false;
}

/**
 * mysqli_real_escape_string standin that insures the DB connection is passed.
 *
 * @param string $string
 * @return string
 */
function db_escape($string) {
	return addslashes($string);
}

/*
 * returns the insert id of the last database insert
 */

function db_insert_id() {
	return 0;
}

/*
 * Fetch a result row as an associative array
 */

function db_fetch_assoc($resource) {
	return false;
}

/*
 * 	returns the error number from the previous operation
 */

function db_errorno() {
	return gettext('No database');
}

/*
 * Returns the text of the error message from previous operation
 */

function db_error() {
	return gettext('No databases are configured.');
}

/*
 * Get number of affected rows in previous operation
 */

function db_affected_rows() {
	return 0;
}

/*
 * Get a result row as an enumerated array
 */

function db_fetch_row($result) {
	return false;
}

/*
 * Get number of rows in result
 */

function db_num_rows($result) {
	return 0;
}

/**
 * Closes the database
 */
function db_close() {
	$_DB_connection = NULL;
	return true;
}

/*
 * report the software of the database
 */

function db_software() {
	return array('application' => DATABASE_SOFTWARE,
			'required' => 'N/A',
			'desired' => 'N/A',
			'version' => '0.0.0',
			'connections' => 0
	);
}

/**
 * create the database
 */
function db_create() {
	return false;
}

/**
 * Returns user's permissions on the database
 */
function db_permissions() {
	return false;
}

/**
 * Sets the SQL session mode to empty
 */
function db_setSQLmode() {
	return false;
}

/**
 * Queries the SQL session mode
 */
function db_getSQLmode() {
	return false;
}

function db_create_table(&$sql) {
	return false;
}

function db_table_update(&$sql) {
	return false;
}

function db_show($what, $aux = '') {
	return false;
}

function db_list_fields($table) {
	return false;
}

function db_truncate_table($table) {
	return false;
}

function db_LIKE_escape($str) {
	return strtr($str, array('_' => '\\_', '%' => '\\%'));
}

function db_free_result($result) {
	return false;
}

?>
