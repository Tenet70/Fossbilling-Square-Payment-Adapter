<?php

/**
 * Square Payment Gateway Adapter for FOSSBilling
 *
 * @license Apache-2.0
 */

use FOSSBilling\InjectionAwareInterface;

class Payment_Adapter_Square implements InjectionAwareInterface
{
    protected ?\Pimple\Container $di = null;

    public function setDi(\Pimple\Container $di): void
    {
        $this->di = $di;
    }

    public function getDi(): ?\Pimple\Container
    {
        return $this->di;
    }

    public function __construct(private array $config)
    {
        if (empty($this->config['access_token']) && empty($this->config['test_access_token'])) {
            throw new \Payment_Exception('Square payment gateway is not configured: missing Access Token.');
        }

        if (empty($this->config['location_id']) && empty($this->config['test_location_id'])) {
            throw new \Payment_Exception('Square payment gateway is not configured: missing Location ID.');
        }
    }

    public static function getConfig(): array
    {
        return [
            'supports_one_time_payments' => true,
            'supports_subscriptions'     => false,
            'description'                => 'Accept credit cards, Apple Pay, and Google Pay via Square Checkout. Set your Square Webhook URL to the IPN Callback URL shown above and subscribe to the payment.updated event.',
            'logo'                       => [
                'logo'   => 'Square/icon.svg',
                'height' => '30px',
                'width'  => '30px',
            ],
            'form' => [
                'access_token' => [
                    'password',
                    [
                        'label'       => 'Production Access Token',
                        'description' => 'Found in Square Developer Dashboard -> Credentials -> Production.',
                        'required'    => false,
                    ],
                ],
                'location_id' => [
                    'text',
                    [
                        'label'       => 'Production Location ID',
                        'description' => 'Found in Square Developer Dashboard -> Locations -> Production.',
                        'required'    => false,
                    ],
                ],
                'webhook_signature_key' => [
                    'password',
                    [
                        'label'       => 'Production Webhook Signature Key',
                        'description' => 'Used to verify incoming Square webhooks (HMAC-SHA256).',
                        'required'    => false,
                    ],
                ],
                'test_access_token' => [
                    'password',
                    [
                        'label'       => 'Sandbox Access Token',
                        'description' => 'Used when Test Mode is enabled.',
                        'required'    => false,
                    ],
                ],
                'test_location_id' => [
                    'text',
                    [
                        'label'       => 'Sandbox Location ID',
                        'description' => 'Used when Test Mode is enabled.',
                        'required'    => false,
                    ],
                ],
                'test_webhook_signature_key' => [
                    'password',
                    [
                        'label'       => 'Sandbox Webhook Signature Key',
                        'description' => 'Used to verify webhooks when Test Mode is enabled.',
                        'required'    => false,
                    ],
                ],
            ],
        ];
    }

    public function getHtml($api_admin, $invoice_id, $subscription): string
    {
        $invoice = $api_admin->invoice_get(['id' => $invoice_id]);
        $invoiceService = $this->di['mod_service']('Invoice');
        $payGatewayService = $this->di['mod_service']('Invoice', 'PayGateway');

        $total = $invoiceService->getTotalWithTax($invoice);
        $currency = strtoupper($invoice['currency']);
        $amountInMinorUnits = $this->toMinorUnits($total, $currency);

        $redirectUrl = $this->config['return_url'] ?? $this->di['tools']->url('invoice/' . $invoice['hash']);

        $payload = [
            'idempotency_key' => sprintf('fb-inv-%d-%s', $invoice['id'], bin2hex(random_bytes(8))),
            'quick_pay'       => [
                'name'        => sprintf('Invoice #%s', $invoice['serie_nr'] ?? $invoice['id']),
                'price_money' => [
                    'amount'   => $amountInMinorUnits,
                    'currency' => $currency,
                ],
                'location_id' => $this->getLocationId(),
            ],
            'checkout_options' => [
                'redirect_url' => $redirectUrl,
            ],
            // Store the FOSSBilling invoice ID so the webhook can match it reliably
            'payment_note' => 'FOSSBilling Invoice #' . $invoice['id'],
        ];

        $response = $this->squareRequest('POST', '/v2/online-checkout/payment-links', $payload);

        if (empty($response['payment_link']['url'])) {
            $err = $response['errors'][0]['detail'] ?? 'Unable to create Square payment link.';
            throw new \Payment_Exception('Square Checkout Error: ' . $err);
        }

        $checkoutUrl = htmlspecialchars($response['payment_link']['url'], ENT_QUOTES, 'UTF-8');

        return sprintf(
            '<div class="text-center">
                <p>Click below to complete your payment securely with Square.</p>
                <a href="%s" class="btn btn-primary btn-lg">Pay Now with Square</a>
            </div>',
            $checkoutUrl
        );
    }

    public function processTransaction($api_admin, $id, $data, $gateway_id): void
    {
        $rawBody = file_get_contents('php://input');
        $signatureHeader = $_SERVER['HTTP_X_SQUARE_HMACSHA256_SIGNATURE'] ?? '';
        $webhookUrl = $this->config['notify_url'] ?? $this->getCurrentUrl();

        if (!$this->verifyWebhookSignature($webhookUrl, $rawBody, $signatureHeader)) {
            throw new \Payment_Exception('Invalid Square webhook signature.');
        }

        $event = json_decode($rawBody, true);
        if (!is_array($event) || empty($event['type'])) {
            throw new \Payment_Exception('Invalid Square webhook payload.');
        }

        // Only process completed payments
        if ($event['type'] !== 'payment.updated') {
            return;
        }

        $payment = $event['data']['object']['payment'] ?? null;
        if (!$payment || ($payment['status'] ?? '') !== 'COMPLETED') {
            return;
        }

        $txnId = $payment['id'] ?? null;
        $note = $payment['note'] ?? '';
        $amountMinor = $payment['amount_money']['amount'] ?? 0;
        $currency = strtoupper($payment['amount_money']['currency'] ?? 'CAD');
        $amount = $this->fromMinorUnits($amountMinor, $currency);

        // Extract FOSSBilling invoice ID from payment_note
        if (!preg_match('/FOSSBilling Invoice #(\d+)/', $note, $matches)) {
            throw new \Payment_Exception('Could not match Square payment to a FOSSBilling invoice.');
        }
        $invoiceId = (int) $matches[1];

        $invoice = $api_admin->invoice_get(['id' => $invoiceId]);

        // Prevent duplicate processing
        if ($invoice['status'] === 'paid') {
            return;
        }

        $txData = [
            'id'         => $id,
            'invoice_id' => $invoiceId,
            'txn_id'     => $txnId,
            'txn_status' => 'complete',
            'amount'     => $amount,
            'currency'   => $currency,
            'type'       => 'payment',
            'status'     => 'processed',
        ];
        $api_admin->invoice_transaction_update($txData);

        // Add funds to client balance and mark invoice paid
        $api_admin->client_balance_add_funds([
            'id'          => $invoice['client']['id'],
            'amount'      => $amount,
            'description' => 'Square Payment #' . $txnId,
            'type'        => 'Square',
            'rel_id'      => $txnId,
        ]);

        $api_admin->invoice_batch_pay_with_credits(['client_id' => $invoice['client']['id']]);
    }

    private function squareRequest(string $method, string $endpoint, array $payload = []): array
    {
        $baseUrl = $this->isTestMode()
            ? 'https://connect.squareupsandbox.com'
            : 'https://connect.squareup.com';

        $ch = curl_init($baseUrl . $endpoint);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => [
                'Square-Version: 2025-01-23',
                'Authorization: Bearer ' . $this->getAccessToken(),
                'Content-Type: application/json',
            ],
            CURLOPT_POSTFIELDS => $payload ? json_encode($payload) : null,
            CURLOPT_TIMEOUT    => 30,
        ]);

        $result = curl_exec($ch);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($result === false) {
            throw new \Payment_Exception('Square API connection failed: ' . $curlError);
        }

        return json_decode($result, true) ?? [];
    }

    private function verifyWebhookSignature(string $url, string $body, string $signatureHeader): bool
    {
        $signatureKey = $this->getWebhookSignatureKey();
        if (empty($signatureKey) || empty($signatureHeader)) {
            return false;
        }

        $expected = base64_encode(hash_hmac('sha256', $url . $body, $signatureKey, true));
        return hash_equals($expected, $signatureHeader);
    }

    private function isTestMode(): bool
    {
        return !empty($this->config['test_mode']);
    }

    private function getAccessToken(): string
    {
        return $this->isTestMode()
            ? ($this->config['test_access_token'] ?? '')
            : ($this->config['access_token'] ?? '');
    }

    private function getLocationId(): string
    {
        return $this->isTestMode()
            ? ($this->config['test_location_id'] ?? '')
            : ($this->config['location_id'] ?? '');
    }

    private function getWebhookSignatureKey(): string
    {
        return $this->isTestMode()
            ? ($this->config['test_webhook_signature_key'] ?? '')
            : ($this->config['webhook_signature_key'] ?? '');
    }

    private function toMinorUnits(float $amount, string $currency): int
    {
        $zeroDecimal = ['JPY', 'KRW', 'VND'];
        return in_array($currency, $zeroDecimal, true)
            ? (int) round($amount)
            : (int) round($amount * 100);
    }

    private function fromMinorUnits(int $amount, string $currency): float
    {
        $zeroDecimal = ['JPY', 'KRW', 'VND'];
        return in_array($currency, $zeroDecimal, true)
            ? (float) $amount
            : round($amount / 100, 2);
    }

    private function getCurrentUrl(): string
    {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '');
    }
}