require 'sinatra/base'
require 'mysql2'
require 'mysql2-cs-bind'
require 'tilt/erubis'
require 'erubis'

require 'sinatra/reloader'
require 'rack-mini-profiler'

module Isucon5
  class AuthenticationError < StandardError; end
  class PermissionDenied < StandardError; end
  class ContentNotFound < StandardError; end
  module TimeWithoutZone
    def to_s
      # IDEA: 文字列の定数化
      strftime("%F %H:%M:%S")
    end
  end
  ::Time.prepend TimeWithoutZone
end

class Isucon5::WebApp < Sinatra::Base
  configure :development do
    require 'pry'
    register Sinatra::Reloader
    use Rack::MiniProfiler
  end

  use Rack::Session::Cookie
  # IDEA: escape_htmlとか重かったりしないだろうか
  set :erb, escape_html: true
  set :public_folder, File.expand_path('../../static', __FILE__)
  #set :sessions, true
  set :session_secret, ENV['ISUCON5_SESSION_SECRET'] || 'beermoris'
  set :protection, true

  helpers do
    def config
      @config ||= {
        db: {
          host: ENV['ISUCON5_DB_HOST'] || 'localhost',
          port: ENV['ISUCON5_DB_PORT'] && ENV['ISUCON5_DB_PORT'].to_i,
          username: ENV['ISUCON5_DB_USER'] || 'root',
          password: ENV['ISUCON5_DB_PASSWORD'],
          database: ENV['ISUCON5_DB_NAME'] || 'isucon5q',
        },
      }
    end

    def db
      return Thread.current[:isucon5_db] if Thread.current[:isucon5_db]
      client = Mysql2::Client.new(
        host: config[:db][:host],
        port: config[:db][:port],
        username: config[:db][:username],
        password: config[:db][:password],
        database: config[:db][:database],
        reconnect: true,
      )
      client.query_options.merge!(symbolize_keys: true)
      Thread.current[:isucon5_db] = client
      client
    end

    def authenticate(email, password)
      # IDEA: 毎回DBに問い合わせて認証するんじゃなくて、rubyでユーザーのハッシュマップをもって存在確認すればクエリ減らせて速くなるんじゃね？
      # あるいはredisなどでオンメモリで持っておく
      # IDEA: users.emailにindexはる？←適当
      query = <<SQL
SELECT u.id AS id, u.account_name AS account_name, u.nick_name AS nick_name, u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
WHERE u.email = ? AND u.passhash = SHA2(CONCAT(?, s.salt), 512)
SQL
      # IDEA: db.xquery().firstしてるし、LIMIT 1にする
      result = db.xquery(query, email, password).first
      unless result
        raise Isucon5::AuthenticationError
      end
      session[:user_id] = result[:id]
      result
    end

    def current_user
      return @user if @user
      unless session[:user_id]
        return nil
      end
      @user = get_user(id: session[:user_id])
      unless @user
        session[:user_id] = nil
        session.clear
        raise Isucon5::AuthenticationError
      end
      @user
    end

    def authenticated!
      unless current_user
        redirect '/login'
      end
    end

    def get_user(id: nil, account_name: '')
      user = nil

      if id
        query = <<SQL
SELECT
id, account_name, nick_name, email,
first_name, last_name, sex, birthday, pref
FROM users INNER JOIN profiles ON users.id = profiles.user_id
WHERE id=? LIMIT 1
SQL
        user = db.xquery(query, id).first
      else
        query = <<SQL
SELECT
id, account_name, nick_name, email,
first_name, last_name, sex, birthday, pref
FROM users INNER JOIN profiles ON users.id = profiles.user_id
WHERE account_name=? LIMIT 1
SQL
        user = db.xquery(query, account_name).first
      end

      raise Isucon5::ContentNotFound unless user
      user
    end

    def user_from_account(account_name)
      get_user(account_name: account_name)
    end

    def is_friend?(another_id)
      # IDEA: 計算結果をメモ化
      user_id = session[:user_id]
      query = 'SELECT COUNT(1) AS cnt FROM relations WHERE (one = ? AND another = ?) OR (one = ? AND another = ?)'
      cnt = db.xquery(query, user_id, another_id, another_id, user_id).first[:cnt]
      cnt.to_i > 0 ? true : false
    end

    def is_friend_account?(account_name)
      is_friend?(user_from_account(account_name)[:id])
    end

    def permitted?(another_id)
      another_id == current_user[:id] || is_friend?(another_id)
    end

    def mark_footprint(user_id)
      if user_id != current_user[:id]
        query = 'INSERT INTO footprints (user_id,owner_id) VALUES (?,?)'
        db.xquery(query, user_id, current_user[:id])
      end
    end

    # IDEA: 文字列の定数化
    PREFS = %w(
      未入力
      北海道 青森県 岩手県 宮城県 秋田県 山形県 福島県 茨城県 栃木県 群馬県 埼玉県 千葉県 東京都 神奈川県 新潟県 富山県
      石川県 福井県 山梨県 長野県 岐阜県 静岡県 愛知県 三重県 滋賀県 京都府 大阪府 兵庫県 奈良県 和歌山県 鳥取県 島根県
      岡山県 広島県 山口県 徳島県 香川県 愛媛県 高知県 福岡県 佐賀県 長崎県 熊本県 大分県 宮崎県 鹿児島県 沖縄県
    )
    def prefectures
      PREFS
    end
  end

  error Isucon5::AuthenticationError do
    session[:user_id] = nil
    halt 401, erubis(:login, layout: false, locals: { message: 'ログインに失敗しました' })
  end

  error Isucon5::PermissionDenied do
    halt 403, erubis(:error, locals: { message: '友人のみしかアクセスできません' })
  end

  error Isucon5::ContentNotFound do
    halt 404, erubis(:error, locals: { message: '要求されたコンテンツは存在しません' })
  end

  get '/login' do
    session.clear
    erb :login, layout: false, locals: { message: '高負荷に耐えられるSNSコミュニティサイトへようこそ!' }
  end

  post '/login' do
    authenticate params['email'], params['password']
    redirect '/'
  end

  get '/logout' do
    session[:user_id] = nil
    session.clear
    redirect '/login'
  end

  get '/' do
    authenticated!
    entries_query = 'SELECT id, body FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
    entries = db.xquery(entries_query, current_user[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }

    comments_for_me_query = <<SQL
SELECT c.comment AS comment, c.created_at AS created_at, account_name, nick_name
FROM comments AS c
INNER JOIN entries AS e ON e.id = c.entry_id
INNER JOIN users ON users.id = c.user_id
WHERE e.user_id = ?
ORDER BY c.id DESC
LIMIT 10
SQL
    comments_for_me = db.xquery(comments_for_me_query, current_user[:id])

    friend_ids = db.xquery('SELECT one, another FROM relations WHERE one = ? OR another = ?', current_user[:id], current_user[:id]).flat_map { |r| [r[:one].to_i, r[:another].to_i] }.uniq - [current_user[:id]]

    entries_for_friends_query = <<SQL
SELECT e.id, e.body, account_name, nick_name, e.created_at FROM entries AS e
INNER JOIN users ON e.user_id = users.id
WHERE users.id IN (?) ORDER BY e.id DESC LIMIT 10
SQL

    entries_of_friends = db.xquery(entries_for_friends_query, friend_ids).each do |entry|
      entry[:title] = entry[:body].split("\n").first
    end

    comments_for_friends_query = <<SQL
SELECT
c.comment,
users.account_name AS comment_account_name,
users.nick_name AS comment_nick_name,
xusers.account_name AS entry_account_name,
xusers.nick_name AS entry_nick_name,
e.user_id AS entry_user_id,
c.created_at
FROM comments AS c
INNER JOIN entries AS e ON e.id = c.entry_id AND (e.user_id IN (?) OR e.private = 0)
INNER JOIN users ON c.user_id = users.id
INNER JOIN users AS xusers ON e.user_id = xusers.id
WHERE c.user_id IN (?) ORDER BY c.created_at DESC LIMIT 10
SQL
    comments_of_friends = db.xquery(comments_for_friends_query, friend_ids, friend_ids)

    query = <<SQL
SELECT account_name, nick_name, DATE(f.created_at) AS date, MAX(f.created_at) AS updated
FROM footprints AS f
INNER JOIN users ON f.owner_id = users.id
INNER JOIN profiles ON users.id = profiles.user_id
WHERE f.user_id = ?
GROUP BY f.user_id, f.owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 10
SQL
    footprints = db.xquery(query, current_user[:id])

    locals = {
      entries: entries,
      comments_for_me: comments_for_me,
      entries_of_friends: entries_of_friends,
      comments_of_friends: comments_of_friends,
      friend_count: friend_ids.count,
      footprints: footprints
    }
    erb :index, locals: locals
  end

  get '/profile/:account_name' do
    authenticated!
    owner = get_user(account_name: params['account_name'])
    prof = {} unless prof
    permitted = permitted?(owner[:id])
    query = if permitted
              # IDEA: 必要なカラムだけSELECTする
              'SELECT id, body, created_at FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
            else
              # IDEA: 必要なカラムだけSELECTする
              'SELECT id, body, created_at FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5'
            end
    entries = db.xquery(query, owner[:id])
      .map{ |entry| entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
    mark_footprint(owner[:id])
    erb :profile, locals: { owner: owner, profile: prof, entries: entries, permitted: permitted }
  end

  post '/profile/:account_name' do
    authenticated!
    if params['account_name'] != current_user[:account_name]
      raise Isucon5::PermissionDenied
    end
    args = [params['first_name'], params['last_name'], params['sex'], params['birthday'], params['pref']]

    prof = db.xquery('SELECT user_id FROM profiles WHERE user_id = ? LIMIT 1', current_user[:id]).first
    if prof
      query = <<SQL
UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?
SQL
      args << current_user[:id]
    else
      query = <<SQL
INSERT INTO profiles (user_id,first_name,last_name,sex,birthday,pref) VALUES (?,?,?,?,?,?)
SQL
      args.unshift(current_user[:id])
    end
    db.xquery(query, *args)
    redirect "/profile/#{params['account_name']}"
  end

  get '/diary/entries/:account_name' do
    authenticated!
    owner = user_from_account(params['account_name'])
    query = if permitted?(owner[:id])
              # IDEA: 必要なカラムだけSELECTする
              # IDEA: LIMIT 20はなに？LIMIT 1で良い？
              # IDEA: created_atのorder by必要なければ消す、あるいはrubyでorderingする
              'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
            else
              # IDEA: 必要なカラムだけSELECTする
              # IDEA: LIMIT 20はなに？LIMIT 1で良い？
              # IDEA: created_atのorder by必要なければ消す、あるいはrubyでorderingする
              'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20'
            end
    entries = db.xquery(query, owner[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
    mark_footprint(owner[:id])
    erb :entries, locals: { owner: owner, entries: entries, myself: (current_user[:id] == owner[:id]) }
  end

  get '/diary/entry/:entry_id' do
    authenticated!

    entry = db.xquery("SELECT entries.id, body, created_at, users.nick_name, users.account_name FROM entries INNER JOIN users ON users.id = entries.user_id WHERE entries.id = ? LIMIT 1", params[:entry_id]).first
    raise Isucon5::ContentNotFound unless entry
    entry[:title], entry[:content] = entry[:body].split("\n", 2)
    if entry[:private] == 1 && !permitted?(current_user[:id])
      raise Isucon5::PermissionDenied
    end

    query = <<SQL
SELECT
c.comment, c.created_at, users.account_name, users.nick_name
FROM comments AS c
INNER JOIN users ON users.id = c.user_id
WHERE c.entry_id = ?
SQL
    entry_comments = db.xquery(query, entry[:id])
    mark_footprint(current_user[:id])
    erb :entry, locals: { entry: entry, comments: entry_comments }
  end

  post '/diary/entry' do
    authenticated!
    query = 'INSERT INTO entries (user_id, private, body) VALUES (?,?,?)'
    body = (params['title'] || "タイトルなし") + "\n" + params['content']
    db.xquery(query, current_user[:id], (params['private'] ? '1' : '0'), body)
    redirect "/diary/entries/#{current_user[:account_name]}"
  end

  post '/diary/comment/:entry_id' do
    authenticated!
    # IDEA: 必要なカラムだけSELECTする
    # IDEA: LIMIT 1つける
    entry = db.xquery('SELECT * FROM entries WHERE id = ?', params['entry_id']).first
    unless entry
      raise Isucon5::ContentNotFound
    end
    entry[:is_private] = (entry[:private] == 1)
    if entry[:is_private] && !permitted?(entry[:user_id])
      raise Isucon5::PermissionDenied
    end
    query = 'INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)'
    db.xquery(query, entry[:id], current_user[:id], params['comment'])
    redirect "/diary/entry/#{entry[:id]}"
  end

  get '/footprints' do
    authenticated!
    query = <<SQL
SELECT user_id, owner_id, DATE(created_at) AS date, MAX(created_at) as updated
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 50
SQL
    footprints = db.xquery(query, current_user[:id])
    erb :footprints, locals: { footprints: footprints }
  end

  get '/friends' do
    authenticated!
    query = <<SQL
SELECT rel.created_at,
users.account_name,
users.nick_name
FROM relations AS rel
LEFT JOIN users ON rel.another = users.id
WHERE one = ? ORDER BY created_at DESC
SQL

    list = db.xquery(query, current_user[:id])
    erb :friends, locals: { friends: list }
  end

  post '/friends/:account_name' do
    authenticated!
    unless is_friend_account?(params['account_name'])
      user = user_from_account(params['account_name'])
      unless user
        raise Isucon5::ContentNotFound
      end
      db.xquery('INSERT INTO relations (one, another) VALUES (?,?), (?,?)', current_user[:id], user[:id], user[:id], current_user[:id])
      redirect '/friends'
    end
  end

  get '/initialize' do
    db.query("DELETE FROM relations WHERE id > 500000")
    db.query("DELETE FROM footprints WHERE id > 500000")
    db.query("DELETE FROM entries WHERE id > 500000")
    db.query("DELETE FROM comments WHERE id > 1500000")
  end
end
