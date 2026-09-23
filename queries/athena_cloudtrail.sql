-- Investigate incidents from the raw CloudTrail logs with Athena.
-- Replace <TRAIL_BUCKET> (terraform output trail_bucket) and <ACCOUNT_ID>.
-- Partition projection means no crawlers or MSCK REPAIR needed.

CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
  eventversion STRING,
  useridentity STRUCT<
    type: STRING, principalid: STRING, arn: STRING, accountid: STRING,
    invokedby: STRING, accesskeyid: STRING, username: STRING,
    sessioncontext: STRUCT<
      attributes: STRUCT<mfaauthenticated: STRING, creationdate: STRING>,
      sessionissuer: STRUCT<type: STRING, principalid: STRING, arn: STRING, accountid: STRING, username: STRING>
    >
  >,
  eventtime STRING,
  eventsource STRING,
  eventname STRING,
  awsregion STRING,
  sourceipaddress STRING,
  useragent STRING,
  errorcode STRING,
  errormessage STRING,
  requestparameters STRING,
  responseelements STRING,
  additionaleventdata STRING,
  requestid STRING,
  eventid STRING,
  readonly STRING,
  resources ARRAY<STRUCT<arn: STRING, accountid: STRING, type: STRING>>,
  eventtype STRING,
  apiversion STRING,
  recipientaccountid STRING,
  sharedeventid STRING,
  vpcendpointid STRING
)
PARTITIONED BY (region STRING, day STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<TRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.region.type' = 'enum',
  'projection.region.values' = 'eu-west-1,us-east-1',
  'projection.day.type' = 'date',
  'projection.day.format' = 'yyyy/MM/dd',
  'projection.day.range' = '2026/01/01,NOW',
  'projection.day.interval' = '1',
  'projection.day.interval.unit' = 'DAYS',
  'storage.location.template' = 's3://<TRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/${region}/${day}'
);

-- Who opened a port, and did the responder close it?
SELECT eventtime, eventname, useridentity.arn AS actor, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE region = 'eu-west-1' AND day >= date_format(current_date - interval '1' day, '%Y/%m/%d')
  AND eventname IN ('AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress')
ORDER BY eventtime;

-- Every attempt to blind logging
SELECT eventtime, eventname, useridentity.arn AS actor, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE day >= date_format(current_date - interval '7' day, '%Y/%m/%d')
  AND eventsource = 'cloudtrail.amazonaws.com'
  AND eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'StartLogging')
ORDER BY eventtime;

-- Timeline of everything one principal did (paste the actor ARN from an alert)
SELECT eventtime, eventsource, eventname, sourceipaddress, errorcode
FROM cloudtrail_logs
WHERE day >= date_format(current_date - interval '1' day, '%Y/%m/%d')
  AND useridentity.arn = '<ACTOR_ARN>'
ORDER BY eventtime;
