$(function() {
  'use strict';
  $('.compute-status').each(function(index, item) {
    var item = $(item);
    var url = item.data('url');
    $.ajax({
      type: 'post',
      url: url,
      success: function(response) {
        item.text(__(response.status));
        // Message may contain escaped HTML breaks from errors_hash; keep html:true
        // only for those breaks — content is escaped server-side.
        item.attr('title', response.message);
        if (response.status === 'OK') {
          item.addClass('label label-success');
        } else {
          item.addClass('label label-danger');
        }
        item.tooltip({ html: true });
      },
    });
  });
});
