let app = new Vue({
    el: '#admin',
    data: {
        email: '',
        password: '',
        smtp_server: '',
        smtp_port: '',
    },
    delimiters: ['${', '}$'],
});

function deleteSender(email) {
    axios.post('/api/delete-sender', {
        email: email,
    }).then(response => {
        window.location.reload();
    }).catch(err => {
        console.log(JSON.stringify(err.response));
        alert(err);
    });
}

function addSender() {
    axios.post('/api/add-sender', {
        email: app.$data.email,
        password: app.$data.password,
        smtp_server: app.$data.smtp_server,
        smtp_port: app.$data.smtp_port,
    }).then(response => {
        window.location.reload();
    }).catch(err => {
        console.log(JSON.stringify(err.response));
        alert(err);
    });
}