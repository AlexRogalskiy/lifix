DROP TABLE IF EXISTS fault_attachment;
DROP TABLE IF EXISTS fault;
DROP TABLE IF EXISTS lifixuser;

CREATE TABLE lifixuser (
  subject VARCHAR(255) PRIMARY KEY,
  email VARCHAR(320) UNIQUE NOT NULL,
  username VARCHAR(64) UNIQUE NOT NULL
);

CREATE TABLE fault (
  id IDENTITY,
  desription VARCHAR(8096),
  opened_by VARCHAR(255),
  opened_on BIGINT,
  closed_by VARCHAR(255),
  closed_on BIGINT,
  FOREIGN KEY (opened_by) REFERENCES lifixuser(subject),
  FOREIGN KEY (closed_by) REFERENCES lifixuser(subject)
);

CREATE TABLE fault_attachment (
  id IDENTITY,
  fault_id BIGINT NOT NULL,
  uri VARCHAR(1024) UNIQUE NOT NULL,
  extension VARCHAR(16) NOT NULL,
  FOREIGN KEY (fault_id) REFERENCES fault(id)
);