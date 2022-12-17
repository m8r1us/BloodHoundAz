# Import Readme

1. Open the apoc.conf (C:\Neo4j\relate-data\dbmss\dbms-<your db id>\conf)
2. add the line: apoc.import.file.enabled=true
3. Copy all the .json files from "..\BloodHoundAz\Collectors" to C:\relate-data\dbmss\dbms-<your db id>\import
4. Copy the ..\BloodHoundAz\Importer\azRolesRelationships.json to C:\relate-data\dbmss\dbms-<your db id>\import
4. Open a cmd
5. cd "C:\Neo4j\relate-data\dbmss\dbms-<your db id>\bin
6. Run "cypher-shell.bat"
7. Login
8. Type: :source ..\BloodHoundAz\Importer\loadDataToNeo4j.txt

