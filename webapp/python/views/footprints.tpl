% rebase("layout")
<h2>あしあとリスト</h2>
<div class="row panel panel-primary" id="footprints">
  <ul class="list-group">
    % for fp in footprints:
      % owner = get_user(fp["owner_id"])
      <li class="list-group-item footprints-footprint">{{fp["updated"]}}: <a href="/profile/{{owner["account_name"]}}">{{owner["nick_name"]}}さん</a>
    % end
  </ul>
</div>
