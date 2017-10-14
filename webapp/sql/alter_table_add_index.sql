ALTER TABLE relations ADD INDEX index_on_relations_one(one);
ALTER TABLE relations ADD INDEX index_on_relations_another(another);
ALTER TABLE relations ADD INDEX index_on_relations_created_at(created_at);

ALTER TABLE profiles ADD INDEX index_on_profiles_user_id(user_id);
ALTER TABLE entries ADD INDEX index_on_entries_user_id(user_id);
alter table entries add index index_on_entries_private(private);
alter table comments add index index_on_comments_created_at(created_at);
