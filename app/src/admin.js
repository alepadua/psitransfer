import Vue from 'vue';
import { httpGet } from "./common/util";
import Admin from './Admin.vue';
import Icon from 'vue-awesome/components/Icon'

function parseDate(str) {
  if(!str) return str;
  return new Date(str);
}

function formatDate(dt) {
  if(dt === null) return "";
  const f = function(d) {
    return d < 10 ? '0' + d : d;
  };
  return dt.getFullYear() + '-' + f(dt.getMonth() + 1) + '-' + f(dt.getDate()) + ' ' + f(dt.getHours()) + ':' + f(dt.getMinutes());
}
function isDate(d) {
  return Object.prototype.toString.call(d) === '[object Date]';
}

Vue.filter('date', function(val, format) {
  if(!isDate(val)) {
    val = parseDate(val);
  }
  return isDate(val) ? formatDate(val, format) : val;
});

Vue.component('icon', Icon);

new Vue({
  el: '#admin',
  data: {
    baseURI: document.head.getElementsByTagName('base')[0].href,
    lang: {},
  },
  async beforeCreate() {
    try {
      this.lang = await httpGet('lang.json');
    } catch (e) {
      console.error('Failed to load translations', e);
    }
  },
  render: h => h(Admin)
});

window.PSITRANSFER_VERSION = PSITRANSFER_VERSION;
