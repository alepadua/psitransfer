<template lang="pug">
  .download-app
    a.btn.btn-sm.btn-info.btn-admin-refresh(@click='login()', :title="$root.lang.refresh || 'Refresh'", v-if="loggedIn")
      icon(name="sync-alt")

    .alert.alert-danger(v-show="error")
      strong
        icon.fa-fw(name="exclamation-triangle")
        |  {{ error }}

    form.well(v-if='!loggedIn', @submit.stop.prevent="login")
      h3 {{ $root.lang.password || 'Password' }}
      .form-group
        input.form-control(type='password', v-model='password', autofocus="")
      p.text-danger(v-show='passwordWrong')
        strong {{ $root.lang.accessDenied || 'Access denied!' }}
      |
      button.btn.btn-primary(type="submit", :disabled="!password")
        icon.fa-fw(name="sign-in-alt")
        |  {{ $root.lang.login || 'login' }}

    div(v-if="loggedIn")
      ul.nav.nav-tabs(style="margin-bottom: 20px;")
        li(:class="{ active: activeTab === 'buckets' }")
          a(@click.prevent="activeTab = 'buckets'", href="#")
            icon.fa-fw(name="folder")
            |  {{ $root.lang.files || 'Files' }}
        li(:class="{ active: activeTab === 'sso' }")
          a(@click.prevent="activeTab = 'sso'", href="#")
            icon.fa-fw(name="shield-alt")
            |  {{ $root.lang.ssoOrgs || 'SSO Organizations' }}

      // Tab 1: Buckets & Files
      div(v-if="activeTab === 'buckets'")
        table.table.table-hover
          thead
            tr
              th SID
              th {{ $root.lang.created || 'Created' }}
              th {{ $root.lang.downloaded || 'Downloaded' }}
              th {{ $root.lang.expire || 'Expire' }}
              th {{ $root.lang.size || 'Size' }}
          template(v-for="(bucket, sid) in db")
            tbody(:class="{expanded: expand===sid}")
              tr.bucket(@click="expandView(sid)")
                td
                  | {{ sid }}
                  icon.pull-right(name="key", v-if="sum[sid].password", :title="$root.lang.passwordProtected || 'Password protected'")
                td {{ sum[sid].created | date }}
                td
                  template(v-if="sum[sid].lastDownload") {{ sum[sid].lastDownload | date}}
                  template(v-else="") -
                td
                  template(v-if="typeof sum[sid].firstExpire === 'number'") {{ sum[sid].firstExpire | date }}
                  template(v-else)  {{ sum[sid].firstExpire }}
                td.text-right {{ humanFileSize(sum[sid].size) }}
            tbody.expanded(v-if="expand === sid")
              template(v-for="file in bucket")
                tr.file
                  td {{ file.metadata.name }}
                  td {{+file.metadata.createdAt | date}}
                  td
                    template(v-if="file.metadata.lastDownload") {{ +file.metadata.lastDownload | date}}
                    template(v-else="") -
                  td
                    template(v-if="typeof file.expireDate === 'number'") {{ file.expireDate | date }}
                    template(v-else) {{ file.expireDate }}
                  td.text-right {{ humanFileSize(file.size) }}
          tfoot
            tr
              td(colspan="3")
              td.text-right(colspan="2") {{ $root.lang.sum || 'Sum' }}: {{ humanFileSize(sizeSum) }}

      // Tab 2: SSO Organizations Management
      div(v-if="activeTab === 'sso'")
        .well
          h4 {{ showOrgForm ? ($root.lang.editSsoOrg || 'Edit Organization SSO') : ($root.lang.addSsoOrg || 'Add Organization SSO') }}
          form(@submit.prevent="saveSsoOrg")
            .row
              .col-md-6
                .form-group
                  label {{ $root.lang.orgDomain || 'Domain (e.g. bank.com)' }}
                  input.form-control(type="text", v-model="orgForm.domain", required, :disabled="editingDomain")
              .col-md-6
                .form-group
                  label {{ $root.lang.orgName || 'Organization Name' }}
                  input.form-control(type="text", v-model="orgForm.name", required)
            .row
              .col-md-6
                .form-group
                  label {{ $root.lang.issuerUrl || 'OIDC Issuer URL' }}
                  input.form-control(type="url", v-model="orgForm.issuerUrl", placeholder="https://auth.company.com")
              .col-md-3
                .form-group
                  label {{ $root.lang.clientId || 'Client ID' }}
                  input.form-control(type="text", v-model="orgForm.clientId")
              .col-md-3
                .form-group
                  label {{ $root.lang.clientSecret || 'Client Secret' }}
                  input.form-control(type="password", v-model="orgForm.clientSecret")
            .checkbox
              label
                input(type="checkbox", v-model="orgForm.requireSso")
                strong  {{ $root.lang.requireSso || 'Require SSO for download' }}
            button.btn.btn-success(type="submit", style="margin-right: 10px;")
              icon.fa-fw(name="save")
              |  {{ $root.lang.save || 'Save' }}
            button.btn.btn-default(type="button", @click="resetOrgForm()", v-if="editingDomain")
              | {{ $root.lang.cancel || 'Cancel' }}

        table.table.table-striped.table-hover
          thead
            tr
              th {{ $root.lang.orgDomain || 'Domain' }}
              th {{ $root.lang.orgName || 'Name' }}
              th {{ $root.lang.requireSso || 'Require SSO' }}
              th {{ $root.lang.issuerUrl || 'Issuer URL' }}
              th.text-right Actions
          tbody
            tr(v-for="(org, domain) in ssoOrgs")
              td
                strong {{ domain }}
              td {{ org.name }}
              td
                span.label.label-success(v-if="org.requireSso !== false") Required
                span.label.label-default(v-else) Optional
              td {{ org.issuerUrl || '-' }}
              td.text-right
                .btn-group
                  button.btn.btn-xs.btn-primary(@click="editSsoOrg(org)") Edit
                  button.btn.btn-xs.btn-danger(@click="deleteSsoOrg(domain)") Delete

</template>


<script>
  import 'vue-awesome/icons/exclamation-triangle';
  import 'vue-awesome/icons/sync-alt';
  import 'vue-awesome/icons/sign-in-alt';
  import 'vue-awesome/icons/key';
  import 'vue-awesome/icons/folder';
  import 'vue-awesome/icons/shield-alt';
  import 'vue-awesome/icons/save';

  export default {
    name: 'app',

    data () {
      return {
        db: {},
        sum: {},
        ssoOrgs: {},
        activeTab: 'buckets',
        loggedIn: false,
        password: '',
        error: '',
        passwordWrong: false,
        expand: false,
        sizeSum: 0,
        showOrgForm: false,
        editingDomain: false,
        orgForm: {
          domain: '',
          name: '',
          requireSso: true,
          issuerUrl: '',
          clientId: '',
          clientSecret: ''
        }
      }
    },

    methods: {
      expandView(sid) {
        if(this.expand === sid) return this.expand = false;
        this.expand = sid;
      },

      login() {
        if(!this.password) return;
        const xhr = new XMLHttpRequest();
        xhr.open('GET', 'admin/data.json');
        xhr.setRequestHeader("x-passwd", this.password);
        xhr.onload = () => {
          if(xhr.status === 200) {
            try {
              this.db = JSON.parse(xhr.responseText);
              this.loggedIn = true;
              this.error = '';
              this.passwordWrong = false;
              this.expandDb();
              this.fetchSsoOrgs();
            }
            catch(e) {
              this.error = e.toString();
            }
          } else {
            if(xhr.status === 403) this.passwordWrong = true;
            else this.error = `${xhr.status} ${xhr.statusText}: ${xhr.responseText}`;
          }
        };
        xhr.send();
      },

      fetchSsoOrgs() {
        if(!this.password) return;
        const xhr = new XMLHttpRequest();
        xhr.open('GET', 'admin/sso-orgs.json');
        xhr.setRequestHeader("x-passwd", this.password);
        xhr.onload = () => {
          if(xhr.status === 200) {
            try {
              this.ssoOrgs = JSON.parse(xhr.responseText);
            } catch(e) {
              console.error(e);
            }
          }
        };
        xhr.send();
      },

      saveSsoOrg() {
        if (!this.orgForm.domain || !this.password) return;
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'admin/sso-orgs.json');
        xhr.setRequestHeader("x-passwd", this.password);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onload = () => {
          if(xhr.status === 200) {
            this.fetchSsoOrgs();
            this.resetOrgForm();
          } else {
            alert(`Error saving SSO Org: ${xhr.responseText}`);
          }
        };
        xhr.send(JSON.stringify(this.orgForm));
      },

      editSsoOrg(org) {
        this.editingDomain = true;
        this.orgForm = {
          domain: org.domain || '',
          name: org.name || '',
          requireSso: org.requireSso !== false,
          issuerUrl: org.issuerUrl || '',
          clientId: org.clientId || '',
          clientSecret: org.clientSecret || ''
        };
      },

      deleteSsoOrg(domain) {
        if (!confirm(`Delete SSO configuration for ${domain}?`)) return;
        const xhr = new XMLHttpRequest();
        xhr.open('DELETE', `admin/sso-orgs/${encodeURIComponent(domain)}`);
        xhr.setRequestHeader("x-passwd", this.password);
        xhr.onload = () => {
          if (xhr.status === 204 || xhr.status === 200) {
            this.fetchSsoOrgs();
            if (this.orgForm.domain === domain) this.resetOrgForm();
          }
        };
        xhr.send();
      },

      resetOrgForm() {
        this.editingDomain = false;
        this.orgForm = {
          domain: '',
          name: '',
          requireSso: true,
          issuerUrl: '',
          clientId: '',
          clientSecret: ''
        };
      },

      expandDb() {
        this.sizeSum = 0;
        Object.keys(this.db).forEach(sid => {
          const bucketSum = {
            firstExpire: Number.MAX_SAFE_INTEGER,
            lastDownload: 0,
            created: Number.MAX_SAFE_INTEGER,
            password: false,
            size: 0
          };
          this.db[sid].forEach(file => {
            bucketSum.size += file.size;
            if(file.metadata._password) {
              bucketSum.password = true;
            }
            if(+file.metadata.createdAt < bucketSum.created) {
              bucketSum.created = +file.metadata.createdAt;
            }
            if(file.metadata.lastDownload && +file.metadata.lastDownload > bucketSum.lastDownload) {
              bucketSum.lastDownload = +file.metadata.lastDownload;
            }
            if(file.metadata.retention === 'one-time') {
              bucketSum.firstExpire = 'one-time';
              file.expireDate = file.metadata.retention;
            }
            else {
              file.expireDate = +file.metadata.createdAt + (+file.metadata.retention * 1000);
              if(bucketSum.firstExpire > file.expireDate) bucketSum.firstExpire = file.expireDate;
            }
          });
          this.sizeSum += bucketSum.size;
          this.$set(this.sum, sid, bucketSum);
        });
      },

      humanFileSize(fileSizeInBytes) {
        let i = -1;
        const byteUnits = [' kB', ' MB', ' GB', ' TB', 'PB', 'EB', 'ZB', 'YB'];
        do {
          fileSizeInBytes = fileSizeInBytes / 1024;
          i++;
        } while(fileSizeInBytes > 1024);
        return Math.max(fileSizeInBytes, 0.00).toFixed(2) + byteUnits[i];
      },

    },

  }
</script>

<style>
  .bucket {
    cursor: pointer;
  }
  .expanded {
    background: #fafafa;
  }
  .expanded .bucket td {
    font-weight: bold;
  }
  tfoot {
    font-weight: bold;
  }
</style>
