<?php

/*
 * compares current database to the release database template and makes
 * updates as needed
 *
 * @author Stephen Billard
 * @Copyright 2016 by Stephen L Billard for use in {@link https://%GITHUB% netPhotoGraphics} and derivatives
 *
 */
$dbSoftware = db_software();
define('FIELD_COMMENT_NPG', 'npg');
define('FIELD_COMMENT_METADATA', 'optional_metadata');
$indexComments = version_compare($dbSoftware['version'], '5.5.0') >= 0;
$utf8mb4 = version_compare($dbSoftware['version'], '5.5.3', '>=');

$database = $orphans = $datefields = array();
$template = unserialize(file_get_contents(CORE_SERVERPATH . 'databaseTemplate'));

if (isset($_SESSION['admin']['db_admin_fields'])) { //	we are in a clone install, be srue admin fields match
	$adminTable = $template['administrators']['fields'];
	foreach ($_SESSION['admin']['db_admin_fields'] as $key => $datum) {
		if (!isset($adminTable[$key])) {
			$template['administrators']['fields'][$key] = $datum;
		}
	}
}
$_DB_Structure_change = FALSE;

//	handle column renaming as the template will assume a drop and add.
$renames = array(
		array('table' => 'images',
				'was' => 'ExifImageHeight',
				'is' => 'EXIFImageHeight',
				'type' => 'tinytext',
				'collation' => $utf8mb4 ? 'utf8mb4_unicode_ci' : 'utf8mb3_unicode_ci',
				'comment' => FIELD_COMMENT_METADATA,
				'quiet' => true),
		array('table' => 'pages',
				'was' => 'author',
				'is' => 'owner',
				'type' => 'tinytext',
				'comment' => FIELD_COMMENT_NPG),
		array('table' => 'pages',
				'was' => 'lastchangeauthor',
				'is' => 'lastchangeuser',
				'type' => 'tinytext',
				'comment' => FIELD_COMMENT_NPG),
		array('table' => 'news',
				'was' => 'author',
				'is' => 'owner', 'type' =>
				'tinytext', 'comment' => FIELD_COMMENT_NPG),
		array('table' => 'news',
				'was' => 'lastchangeauthor',
				'is' => 'lastchangeuser',
				'type' => 'tinytext',
				'comment' => FIELD_COMMENT_NPG),
		array('table' => 'comments',
				'was' => 'custom_data',
				'is' => 'address_data',
				'type' => 'text',
				'comment' => FIELD_COMMENT_NPG)
);
foreach ($renames as $change) {
	$sql = 'ALTER TABLE ' . prefix($change['table']) . ' CHANGE `' . $change['was'] . '` `' . $change['is'];
	if (isset($change['type'])) {
		$sql .= '` ' . $change['type'];
	}
	if (isset($change['collation'])) {
		$sql .= " COLLATE " . $change['collation'];
	}
	if (isset($change['comment'])) {
		$sql .= " COMMENT '" . $change['comment'] . "'";
	}

	if (setupQuery($sql, FALSE, !isset($change['quiet']))) {
		if (!isset($change['quiet'])) {
			$_DB_Structure_change = TRUE;
		}
	}
}
unset($_tableFields);

$tagkeys = query_full_array('SHOW KEYS FROM ' . prefix('tags'));
foreach ($tagkeys as $tagkey) {
	if ($tagkey['Column_name'] == 'name' && is_null($tagkey['Sub_part'])) {
		//	set key size so changing the  tag:name field to utf8mb4 succeeds
		query("ALTER TABLE " . prefix('tags') . " DROP INDEX `name`, ADD UNIQUE `name` (`name`(191), `language`) USING BTREE COMMENT 'npg'");
	}
}

foreach (getDBTables() as $table) {
	$tablecols = db_list_fields($table);
	foreach ($tablecols as $key => $datum) {
		//remove don't care fields
		unset($datum['Key']);
		unset($datum['Extra']);
		unset($datum['Privileges']);
		$database[$table]['fields'][$datum['Field']] = $datum;

		if ($datum['Type'] == 'datetime') {
			$datefields[] = array('table' => $table, 'field' => $datum['Field']);
		}
	}

	$indices = array();
	$sql = 'SHOW KEYS FROM ' . prefix($table);
	$result = query_full_array($sql);
	foreach ($result as $index) {
		if ($index['Key_name'] !== 'PRIMARY') {
			$indices[$index['Key_name']][] = $index;
		}
	}
	foreach ($indices as $keyname => $index) {
		if (count($index) > 1) {
			$size = $column = array();
			foreach ($index as $element) {
				$column[] = "`" . $element['Column_name'] . "`";
				$size[] = $element['Sub_part'];
			}
			$index = reset($index);
			$index['Column_name'] = implode(',', $column);
			$index['Size'] = implode(',', $size);
		} else {
			$index = reset($index);
			$index['Column_name'] = "`" . $index['Column_name'] . "`";
		}
		unset($index['Table']);
		unset($index['Seq_in_index']);
		unset($index['Cardinality']);
		unset($index['Comment']);
		unset($index['Visible']);
		unset($index['Expression']);

		if (!$indexComments) {
			unset($index['Index_comment']);
		}

		switch ($keyname) {
			case 'valid':
			case 'user':
				$keys = explode(',', $index['Column_name']);
				sort($keys);
				if ($table == 'administrators' && implode(',', $keys) === '`user`,`valid`') {
					$index['Index_comment'] = FIELD_COMMENT_NPG;
				}
				break;
			case 'filename':
				$keys = explode(',', $index['Column_name']);
				sort($keys);
				if ($table == 'images' && implode(',', $keys) === '`albumid`,`filename`') {
					$index['Index_comment'] = FIELD_COMMENT_NPG;
				}
				break;
			case 'folder':
				if ($table == 'albums' && $index['Column_name'] === '`folder`') {
					$index['Index_comment'] = FIELD_COMMENT_NPG;
				}
				break;
		}
		$database[$table]['keys'][$keyname] = $index;
	}
}

$npgUpgrade = isset($database['administrators']['fields']['valid']['Comment']) && $database['administrators']['fields']['valid']['Comment'] == FIELD_COMMENT_NPG;

//metadata display and disable options

$disable = getSerializedArray(getOption('metadata_disabled'));
$display = getSerializedArray(getOption('metadata_displayed'));

//	Add in the enabled image metadata fields
$metadataProviders = array('class-image' => 'image', 'class-video' => 'Video', 'xmpMetadata' => 'xmpMetadata');
foreach ($metadataProviders as $source => $handler) {
	if ($source == 'class-image') {
		$enabled = true;
	} else {
		$plugin = getPlugin($source . '.php');
		require_once($plugin);
		$enabled = extensionEnabled($source);
	}

	$exifvars = $handler::getMetadataFields();
	ksort($exifvars, SORT_FLAG_CASE | SORT_NATURAL);

	foreach ($exifvars as $key => $exifvar) {
		$disp = getOption($key);
		if (is_null($disp)) {
			$exifvars[$key][METADATA_DISPLAY] = isset($display[$key]);
			$exifvars[$key][METADATA_FIELD_ENABLED] = $exifvar[METADATA_FIELD_ENABLED] = !isset($disable[$key]);
		} else {
			//	cleanup old metadata options
			if (getOption($key . '-disabled')) {
				$exifvars[$key][METADATA_DISPLAY] = $exifvars[$key][METADATA_FIELD_ENABLED] = $exifvar[METADATA_FIELD_ENABLED] = false;
				$disable[$key] = $key;
			} else {
				if ($disp) {
					$exifvars[$key][METADATA_DISPLAY] = true;
					$display[$key] = $key;
				}
				$exifvars[$key][METADATA_FIELD_ENABLED] = $exifvar[METADATA_FIELD_ENABLED] = true;
				$disable[$key] = $key;
			}
			purgeOption($key);
			purgeOption($key . '-disabled');
		}

		$size = $exifvar[METADATA_FIELD_SIZE];
		if ($enabled && $exifvar[METADATA_FIELD_ENABLED]) {
			if ($size > 0) {
				switch ($exifvar[METADATA_FIELD_TYPE]) {
					default:
					case 'string':
						if ($size < 256) {
							$type = 'tinytext';
						} else {
							$type = "text";
						}
						if ($utf8mb4) {
							$collation = 'utf8mb4_unicode_ci';
						} else {
							$collation = 'utf8mb3_unicode_ci';
						}
						break;
					case 'number':
						$type = 'tinytext';
						$collation = 'utf8mb3_unicode_ci';
						break;
					case 'datetime':
						$type = 'datetime';
						$collation = NULL;
						break;
					case 'date':
						$type = 'date';
						$collation = NULL;
						break;
					case 'time':
						$type = 'time';
						$collation = NULL;
						break;
				}
				$field = array(
						'Field' => $key,
						'Type' => $type,
						'Collation' => $collation,
						'Null' => 'YES',
						'Default' => null,
						'Comment' => FIELD_COMMENT_METADATA
				);
				$template['images']['fields'][$key] = $field;
			}
		} else {
			if (isset($database['images']['fields'][$key])) {
				$database['images']['fields'][$key]['Comment'] = FIELD_COMMENT_METADATA;
			}
		}
	}
}

//cleanup datetime where value = '0000-00-00 00:00:00'
foreach ($datefields as $fix) {
	$table = $fix['table'];
	$field = $fix['field'];
	$sql = 'UPDATE ' . prefix($table) . ' SET `' . $field . '`=NULL WHERE `' . $field . '`="0000-00-00 00:00:00"';
	setupQuery($sql, FALSE, FALSE);
}

//setup database
$result = db_show('variables', 'character_set_database');
if (is_array($result)) {
	$row = reset($result);
	$dbmigrate = $row['Value'] != 'utf8mb4';
} else {
	$dbmigrate = true;
}

if ($utf8mb4) {
	if ($dbmigrate) {
		$sql = 'ALTER DATABASE `' . db_name() . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;';
		if (setupQuery($sql)) {
			$_DB_Structure_change = TRUE;
		}
	}
} else {
	// change the template to utf8mb3_unicode_ci
	foreach ($template as $tablename => $table) {
		foreach ($table['fields'] as $key => $field) {
			if ($field['Collation'] == 'utf8mb4_unicode_ci') {
				$template[$tablename]['fields'][$key]['Collation'] = 'utf8mb3_unicode_ci';
			}
		}
	}
}

$uniquekeys = $tablePresent = array();
foreach ($template as $tablename => $table) {
	$tablePresent[$tablename] = $exists = array_key_exists($tablename, $database);
	$dborder = array();
	if ($exists) {
		if (isset($database[$tablename]['fields'])) {
			$dborder = array_keys($database[$tablename]['fields']);
		}
	} else {
		$create = array();
		$create[] = "CREATE TABLE IF NOT EXISTS " . prefix($tablename) . " (";
		$create[] = "  `id` int UNSIGNED NOT NULL auto_increment,";
	}
	$after = ' FIRST';
	$templateorder = array_keys($table['fields']);

	foreach ($table['fields'] as $key => $field) {
		if ($key != 'id') {
			$dbType = strtoupper($field['Type']);
			$string = "ALTER TABLE " . prefix($tablename) . " %s `" . $field['Field'] . "` " . $dbType;
			switch ($field['Collation']) {
				case 'utf8mb4_0900_as_ci':
				case 'utf8mb4_bin':
					$string .= ' CHARACTER SET utf8mb4 COLLATE ' . UTF8MB4_AS_FIELD_COLLATION;
					$field['Collation'] = UTF8MB4_AS_FIELD_COLLATION; //	avoid DB update notice
					break;
				case 'utf8mb4_unicode_ci':
					$string .= ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
					break;
				case 'utf8_unicode_ci':
				case 'utf8mb3_unicode_ci':
					$string .= ' CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci';
					$field['Collation'] = 'utf8mb3_unicode_ci';
					break;
				case 'utf8mb3_bin':
					$string .= ' CHARACTER SET utf8mb3 COLLATE utf8mb3_bin';
					break;
			}
			if ($field['Null'] === 'NO') {
				$string .= " NOT NULL";
			}
			if (!empty($field['Default']) || $field['Default'] === '0' || $field['Null'] !== 'NO') {
				if (is_null($field['Default'])) {
					if ($field['Null'] !== 'NO') {
						$string .= " DEFAULT NULL";
					}
				} else {
					$string .= " DEFAULT '" . $field['Default'] . "'";
				}
			}
			if (empty($field['Comment'])) {
				$comment = '';
			} else {
				$comment = " COMMENT '" . $field['Comment'] . "'";
			}
			$addString = sprintf($string, 'ADD COLUMN') . $comment . $after . ';';
			$changeString = sprintf($string, "CHANGE `" . $field['Field'] . "`") . $comment . $after . ';';

			if ($exists) {
				if (isset($database[$tablename]['fields']) && array_key_exists($key, $database[$tablename]['fields'])) {
					if (strpos(strtolower($field['Type']), 'int') !== false) {
						$database[$tablename]['fields'][$key]['Type'] = preg_replace('`\(\d*\)`', '', $database[$tablename]['fields'][$key]['Type']);
					}
					if (isset($database[$tablename]['fields'][$key]['Collation']) && $database[$tablename]['fields'][$key]['Collation'] === 'utf8_unicode_ci') {
						$database[$tablename]['fields'][$key]['Collation'] = 'utf8mb3_unicode_ci';
					}
					if ($field != $database[$tablename]['fields'][$key] || array_search($key, $templateorder) != array_search($key, $dborder)) {
						if (setupQuery($changeString)) {
							$_DB_Structure_change = TRUE;
						}
					}
				} else {
					if (setupQuery($addString)) {
						$_DB_Structure_change = TRUE;
					}
				}
			} else {
				$x = preg_split('/%s /', $string);
				$create[] = "  " . $x[1] . $comment . ',';
			}
		}
		$after = ' AFTER `' . $field['Field'] . '`';

		unset($database[$tablename]['fields'][$key]);
	}
	if ($exists) {
		//handle surplus fields
		foreach ($database[$tablename]['fields'] as $key => $field) {
			// drop fields no longer used
			if ($field['Comment'] === FIELD_COMMENT_NPG || $field['Comment'] === FIELD_COMMENT_METADATA) {
				$dropString = "ALTER TABLE " . prefix($tablename) . " DROP `" . $field['Field'] . "`;";
				if (setupQuery($dropString)) {
					$_DB_Structure_change = TRUE;
				}
			} else {
				if (strpos($field['Comment'], 'optional_') === false) {
					$orphans[] = array('type' => 'field', 'table' => $tablename, 'item' => $key, 'message' => sprintf(gettext('Setup found the field "%1$s" in the "%2$s" table. This field is not in use by netPhotoGraphics.'), $key, $tablename));
				}
			}
		}
	}
	if (isset($table['keys'])) {
		foreach ($table['keys'] as $key => $index) {
			$string = "ALTER TABLE " . prefix($tablename) . ' ADD ';
			$k = $index['Column_name'];
			$i = explode(',', $k);
			if (isset($index['Size'])) {
				if (count($i) > 1) {
					$k = '';
					$s = explode(',', $index['Size']);
					foreach ($i as $ix => $v) {
						if ($s[$ix]) {
							$v .= '(' . $s[$ix] . ')';
						}
						$k .= $v . ',';
					}
					$k = rtrim($k, ',');
				}
			} else {
				$k .= $index['Sub_part'];
			}

			if ($index['Non_unique']) {
				$string .= "INDEX ";
				$u = "KEY";
			} else {
				$string .= "UNIQUE ";
				$u = "UNIQUE `$key`";
				$uniquekeys[$tablename][$key] = $i;
			}

			$alterString = "$string`$key` ($k)";
			if ($indexComments) {
				$alterString .= " COMMENT '" . FIELD_COMMENT_NPG . "';";
			} else {
				unset($index['Index_comment']);
			}
			if ($exists) {
				if (isset($database[$tablename]['keys'][$key])) {
					unset($database[$tablename]['keys'][$key]['Visible']);
					unset($database[$tablename]['keys'][$key]['Expression']);
					if ($index != $database[$tablename]['keys'][$key]) {
						setupQuery('LOCK TABLES ' . prefix($tablename) . ' WRITE');
						$dropString = "ALTER TABLE " . prefix($tablename) . " DROP INDEX `" . $index['Key_name'] . "`;";
						if (setupQuery($dropString)) {
							$_DB_Structure_change = TRUE;
						}
						if (setupQuery($alterString)) {
							$_DB_Structure_change = TRUE;
						}
						setupQuery('UNLOCK TABLES');
					}
				} else {
					if (setupQuery($alterString)) {
						$_DB_Structure_change = TRUE;
					}
				}
			} else {
				$tableString = "  $u ($k)";
				if ($indexComments) {
					$tableString .= "  COMMENT '" . FIELD_COMMENT_NPG . "'";
				}
				$create[] = $tableString . ',';
			}
			unset($database[$tablename]['keys'][$key]);
		}
	}
	if (!$exists) {
		$create[] = "  PRIMARY KEY (`id`)";
		$create[] = ")  CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci;";
		$create = implode("\n", $create);
		if (setupQuery($create)) {
			$_DB_Structure_change = TRUE;
		}
	} else {
		//handle surplus fields
		if (array_key_exists('keys', $database[$tablename]) && !empty($database[$tablename]['keys'])) {
			foreach ($database[$tablename]['keys'] as $index) {
				$key = $index['Key_name'];
				if (isset($index['Index_comment']) && $index['Index_comment'] === FIELD_COMMENT_NPG) {
					$dropString = "ALTER TABLE " . prefix($tablename) . " DROP INDEX `" . $key . "`;";
					if (setupQuery($dropString)) {
						$_DB_Structure_change = TRUE;
					}
				} else {
					$orphans[] = array('type' => 'index', 'table' => $tablename, 'item' => $key, 'message' => sprintf(gettext('Setup found the key "%1$s" in the "%2$s" table. This index is not in use by netPhotoGraphics.'), $key, $tablename));
				}
			}
		}
	}
}

if ($_DB_Structure_change) {
	//	force metadata refresh
	$sql = "UPDATE " . prefix('albums') . " SET `mtime`=0;";
	query($sql);
	$sql = "UPDATE " . prefix('images') . " SET `mtime`=0;";
	query($sql);
}

foreach ($uniquekeys as $table => $keys) {
	foreach ($keys as $unique => $components) {
		$updateErrors = $updateErrors || checkUnique(prefix($table), array_flip(array_map(function ($item) {
															return trim($item, '`');
														}, $components)));
	}
}
//if this is a new database, update the config file for the utf8 encoding
if ($utf8mb4 && !array_search(true, $tablePresent)) {
	$_config_contents = file_exists(SERVERPATH . '/' . DATA_FOLDER . '/' . CONFIGFILE) ? file_get_contents(SERVERPATH . '/' . DATA_FOLDER . '/' . CONFIGFILE) : NULL;
	$_config_contents = configFile::update('UTF-8', 'utf8mb4', $_config_contents);
	configFile::store($_config_contents);
}
// now the database is setup we can store the options
setOptionDefault('metadata_disabled', serialize($disable));
setOptionDefault('metadata_displayed', serialize($display));

//	Don't report these unless npg has previously been installed because the
//	plugins which might "claim" them will not yet have run
if ($npgUpgrade) {
	$sql = 'DELETE FROM ' . prefix('plugin_storage') . ' WHERE `type` LIKE ' . db_quote('db_orpahned_%');
	query($sql);
	if (!empty($orphans)) {
		foreach ($orphans as $orphan) {
			$message = $orphan['message'];
			$sql = 'INSERT INTO ' . prefix('plugin_storage') . '(`type`,`subtype`,`aux`) VALUES ("db_orpahned_' . $orphan['type'] . '",' . db_quote($orphan['table']) . ',' . db_quote($orphan['item']) . ')';
			query($sql);
			setupLog($message, TRUE);
		}
	}
}
?>