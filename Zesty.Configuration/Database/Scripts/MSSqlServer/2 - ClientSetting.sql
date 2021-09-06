insert into [dbo].[ClientSetting] ([Key], [Value]) VALUES ('regex.password','^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$');
