const BidExporter = {
    toCSV(bids, type) {
        if (!bids || !bids.length) {
            return 'No data to export';
        }

        const isAllTab = type === 'all';

        const headers = [
            'Date/Time',
            'Bid ID',
            'Offer ID',
            'From Address',
            ...(isAllTab ? ['Type'] : []),
            'You Send Amount',
            'You Send Coin',
            'You Receive Amount',
            'You Receive Coin',
            'Status',
            'Created At',
            'Expires At'
        ];

        let csvContent = headers.join(',') + '\n';

        bids.forEach(bid => {
            const isSent = isAllTab ? (bid.source === 'sent') : (type === 'sent');
            const row = [
                `"${formatTime(bid.created_at)}"`,
                `"${bid.bid_id}"`,
                `"${bid.offer_id}"`,
                `"${bid.addr_from}"`,
                ...(isAllTab ? [`"${bid.source}"`] : []),
                isSent ? bid.amount_from : bid.amount_to,
                `"${isSent ? bid.coin_from : bid.coin_to}"`,
                isSent ? bid.amount_to : bid.amount_from,
                `"${isSent ? bid.coin_to : bid.coin_from}"`,
                `"${bid.bid_state}"`,
                bid.created_at,
                bid.expire_at
            ];

            csvContent += row.join(',') + '\n';
        });

        return csvContent;
    },

    download(content, filename) {
        try {
            const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });

            if (window.navigator && window.navigator.msSaveOrOpenBlob) {
                window.navigator.msSaveOrOpenBlob(blob, filename);
                return;
            }

            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');

            link.href = url;
            link.download = filename;
            link.style.display = 'none';

            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            setTimeout(() => {
                URL.revokeObjectURL(url);
            }, 100);
        } catch (error) {
            console.error('Error downloading CSV:', error);

            const csvData = 'data:text/csv;charset=utf-8,' + encodeURIComponent(content);
            const link = document.createElement('a');
            link.setAttribute('href', csvData);
            link.setAttribute('download', filename);
            link.style.display = 'none';

            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    },

    exportCurrentView() {
        const type = state.currentTab;
        const data = state.data[type];

        if (!data || !data.length) {
            alert('No data to export');
            return;
        }

        const csvContent = this.toCSV(data, type);

        const now = new Date();
        const dateStr = now.toISOString().split('T')[0];
        const filename = `bsx_${type}_bids_${dateStr}.csv`;

        this.download(csvContent, filename);
    }
};

document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        if (typeof state !== 'undefined' && typeof EventManager !== 'undefined') {
            const exportAllButton = document.getElementById('exportAllBids');
            if (exportAllButton) {
                EventManager.add(exportAllButton, 'click', (e) => {
                    e.preventDefault();
                    state.currentTab = 'all';
                    BidExporter.exportCurrentView();
                });
            }

            const exportSentButton = document.getElementById('exportSentBids');
            if (exportSentButton) {
                EventManager.add(exportSentButton, 'click', (e) => {
                    e.preventDefault();
                    state.currentTab = 'sent';
                    BidExporter.exportCurrentView();
                });
            }

            const exportReceivedButton = document.getElementById('exportReceivedBids');
            if (exportReceivedButton) {
                EventManager.add(exportReceivedButton, 'click', (e) => {
                    e.preventDefault();
                    state.currentTab = 'received';
                    BidExporter.exportCurrentView();
                });
            }
        }
    }, 500);
});

const originalCleanup = window.cleanup || function(){};
window.cleanup = function() {
    originalCleanup();

    const exportAllButton = document.getElementById('exportAllBids');
    const exportSentButton = document.getElementById('exportSentBids');
    const exportReceivedButton = document.getElementById('exportReceivedBids');

    if (exportAllButton && typeof EventManager !== 'undefined') {
        EventManager.remove(exportAllButton, 'click');
    }
    
    if (exportSentButton && typeof EventManager !== 'undefined') {
        EventManager.remove(exportSentButton, 'click');
    }

    if (exportReceivedButton && typeof EventManager !== 'undefined') {
        EventManager.remove(exportReceivedButton, 'click');
    }
};
